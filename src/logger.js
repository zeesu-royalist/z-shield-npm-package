'use strict';

const fs = require('node:fs');
const path = require('node:path');

/**
 * Strips ANSI terminal escape codes from untrusted strings to prevent terminal injection.
 * @param {string} str
 * @returns {string}
 */
function stripAnsi(str) {
  // Matches standard ANSI color and control escape sequences
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
}

/**
 * Sanitizes an untrusted string to prevent Log Injection (CWE-117).
 * - Strips ANSI escapes
 * - Strips control characters (newlines \r, \n, null bytes, backspaces, tabs)
 * - Truncates to maxLength to prevent disk space exhaustion
 *
 * @param {*} val
 * @param {number} [maxLength=250]
 * @returns {string}
 */
function sanitizeString(val, maxLength = 250) {
  if (val === null || val === undefined) {
    return '';
  }
  let str = String(val);
  str = stripAnsi(str);
  // Replace control characters (ASCII 0-31, 127) with a clean space
  str = str.replace(/[\x00-\x1f\x7f]/g, ' ').trim();
  // Collapse consecutive spaces
  str = str.replace(/\s+/g, ' ');
  return str.slice(0, maxLength);
}

/**
 * Sanitizes HTTP route paths.
 * @param {*} route
 * @param {number} [maxLength=500]
 * @returns {string}
 */
function sanitizeRoute(route, maxLength = 500) {
  if (!route || typeof route !== 'string') {
    return '/';
  }
  let clean = route.split(/[\r\n]/)[0];
  clean = stripAnsi(clean);
  // Strip query parameters and URL fragments to prevent credential leakage (CWE-532)
  clean = clean.split('?')[0].split('#')[0];
  // Remove dangerous control characters and newlines
  clean = clean.replace(/[\x00-\x1f\x7f]/g, '').trim();
  if (!clean.startsWith('/')) {
    clean = '/' + clean;
  }
  return clean.slice(0, maxLength);
}

/**
 * Sanitizes HTTP methods.
 * @param {*} method
 * @returns {string}
 */
function sanitizeMethod(method) {
  if (!method || typeof method !== 'string') {
    return 'GET';
  }
  const clean = method.toUpperCase().replace(/[^A-Z]/g, '');
  return clean.slice(0, 10) || 'GET';
}

/**
 * Logger - Safe, Persistent Local JSON Lines Security Event Logger
 *
 * Design Features:
 * - JSON Lines (.jsonl): Every event is on exactly one line ending in \n.
 * - Non-Blocking & Asynchronous: Uses node:fs/promises without blocking the event loop.
 * - Strict Sanitization: Eliminates Log Injection (CWE-117) by stripping newlines and ANSI escapes.
 * - Privacy-Preserving: Never logs passwords, cookies, authorization headers, or request bodies (CWE-532).
 * - Bounded Storage: Automatic log rotation and retention limits prevent disk space exhaustion.
 * - Resilient: Filesystem errors (ENOSPC, EACCES) are safely caught and will not crash the host app.
 * - Sequential Queue: Guarantees concurrency safety so simultaneous writes never corrupt files.
 *
 * Hosting Notice:
 * Logs are stored in local persistent storage. If deployed to ephemeral platforms
 * (e.g. basic Heroku dynos, AWS Lambda, or serverless containers without mounted volumes),
 * local log files may be lost upon container restart or redeployment.
 */
class Logger {
  /**
   * @param {Object} [config={}] - Resolved Z-Shield configuration
   */
  constructor(config = {}) {
    this.appName = config.appName || 'default-app';
    this.logDir = path.resolve(config.logDir || path.join(process.cwd(), '.z-shield-logs'));
    this.logFilename = config.logFilename || 'events.jsonl';
    this.filePath = path.join(this.logDir, this.logFilename);
    this.maxLogSizeBytes = config.maxLogSizeBytes || 5 * 1024 * 1024; // 5MB
    this.maxLogFiles = typeof config.maxLogFiles === 'number' ? config.maxLogFiles : 5;
    this.onLogError = typeof config.onLogError === 'function' ? config.onLogError : null;

    this._writeQueue = Promise.resolve();
    this._dirEnsured = false;
  }

  /**
   * Formats and sanitizes a security event into a validated schema.
   * Deliberately omits request bodies, authorization headers, cookies, and tokens.
   *
   * @param {Object} rawEvent
   * @returns {Object} Validated security event
   */
  formatEvent(rawEvent = {}) {
    const now = rawEvent.timestamp ? new Date(rawEvent.timestamp) : new Date();
    const timestamp = isNaN(now.getTime()) ? new Date().toISOString() : now.toISOString();

    const allowedSeverities = ['info', 'warning', 'critical'];
    const severity = allowedSeverities.includes(rawEvent.severity) ? rawEvent.severity : 'warning';

    const allowedActions = ['blocked', 'warned', 'allowed', 'unblocked'];
    const action = allowedActions.includes(rawEvent.action) ? rawEvent.action : 'warned';

    return {
      timestamp,
      appName: sanitizeString(rawEvent.appName || this.appName, 50),
      type: sanitizeString(rawEvent.type || 'security_event', 30),
      severity,
      ip: sanitizeString(rawEvent.ip || 'unknown', 45),
      method: sanitizeMethod(rawEvent.method),
      route: sanitizeRoute(rawEvent.route),
      reason: sanitizeString(rawEvent.reason || 'Unspecified security event', 300),
      action
    };
  }

  /**
   * Safely logs a security event asynchronously.
   * Resolves to true if write succeeded, or false if it failed.
   *
   * @param {Object} rawEvent
   * @returns {Promise<boolean>}
   */
  log(rawEvent) {
    return new Promise((resolve) => {
      this._writeQueue = this._writeQueue
        .then(() => this._writeEvent(rawEvent))
        .then(() => resolve(true))
        .catch((err) => {
          this._handleError(err, rawEvent);
          resolve(false);
        });
    });
  }

  /**
   * Waits for all currently queued asynchronous log writes to complete.
   * Useful for deterministic testing, graceful shutdowns, and process exit handlers.
   *
   * @returns {Promise<void>}
   */
  async flush() {
    await this._writeQueue;
  }

  /**
   * Internal write operation executed within the sequential queue.
   *
   * @private
   * @param {Object} rawEvent
   */
  async _writeEvent(rawEvent) {
    const event = this.formatEvent(rawEvent);
    await this._ensureDir();
    await this._rotateIfNeeded();

    const line = JSON.stringify(event) + '\n';
    await fs.promises.appendFile(this.filePath, line, { encoding: 'utf8', flag: 'a' });
  }

  /**
   * Ensures the target log directory exists.
   * @private
   */
  async _ensureDir() {
    if (!this._dirEnsured) {
      await fs.promises.mkdir(this.logDir, { recursive: true });
      this._dirEnsured = true;
    }
  }

  /**
   * Checks file size and rotates log files if size exceeds maxLogSizeBytes.
   * @private
   */
  async _rotateIfNeeded() {
    try {
      const stats = await fs.promises.stat(this.filePath);
      if (stats.size < this.maxLogSizeBytes) {
        return;
      }
    } catch (err) {
      if (err.code === 'ENOENT') {
        return; // File does not exist yet
      }
      throw err;
    }

    const { name, ext } = path.parse(this.logFilename);

    // If maxLogFiles is 0, simply remove the current file
    if (this.maxLogFiles === 0) {
      try {
        await fs.promises.unlink(this.filePath);
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
      return;
    }

    // Shift existing rotated files:
    // e.g. events.5.jsonl deleted (retention limit)
    // events.4.jsonl -> events.5.jsonl
    // events.1.jsonl -> events.2.jsonl
    for (let i = this.maxLogFiles; i >= 1; i--) {
      const currentRotated = path.join(this.logDir, `${name}.${i}${ext}`);
      if (i === this.maxLogFiles) {
        try {
          await fs.promises.unlink(currentRotated);
        } catch (err) {
          if (err.code !== 'ENOENT') throw err;
        }
      } else {
        const nextRotated = path.join(this.logDir, `${name}.${i + 1}${ext}`);
        try {
          await fs.promises.rename(currentRotated, nextRotated);
        } catch (err) {
          if (err.code !== 'ENOENT') throw err;
        }
      }
    }

    // Move current events.jsonl to events.1.jsonl
    const firstRotated = path.join(this.logDir, `${name}.1${ext}`);
    try {
      await fs.promises.rename(this.filePath, firstRotated);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }

  /**
   * Safely handles write and filesystem failures without crashing the application.
   *
   * @private
   * @param {Error} err
   * @param {Object} rawEvent
   */
  _handleError(err, rawEvent) {
    if (this.onLogError) {
      try {
        this.onLogError(err, rawEvent);
      } catch {
        // Prevent errors in the user's callback from crashing the app
      }
    } else {
      // Print clear, non-fatal warning to stderr
      console.error(`[Z-Shield Logger Warning]: Failed to write security event log: ${err.message}`);
    }
  }
}

module.exports = {
  Logger,
  sanitizeString,
  sanitizeRoute,
  sanitizeMethod,
  stripAnsi
};
