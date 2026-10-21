import fs from 'node:fs';
import path from 'node:path';
import type { ZShieldConfig, ZShieldOptions } from './types';

export interface LoggerOptions {
  appName?: string;
  logDir?: string;
  logFilename?: string;
  maxLogSizeBytes?: number;
  maxLogFiles?: number;
  maxLogQueueSize?: number;
  maxQueueSize?: number;
  onLogError?: ((err: Error, event: Record<string, unknown>) => void) | null;
}

export interface FormattedSecurityEvent {
  timestamp: string;
  appName: string;
  type: string;
  severity: string;
  ip: string;
  method: string;
  route: string;
  reason: string;
  action: string;
}

const ANSI_REGEX =
  /[\u001B\u009B](?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])/g;

/**
 * Strips ANSI terminal escape codes from untrusted strings to prevent terminal injection.
 * Removes CSI color/control sequences, OSC title/hyperlink sequences, and escape codes.
 *
 * @param str - Untrusted string
 * @returns Clean string without ANSI escapes
 */
export function stripAnsi(str: string): string {
  if (typeof str !== 'string') {
    return '';
  }
  return str.replace(ANSI_REGEX, '');
}

/**
 * Sanitizes an untrusted string to prevent Log Injection (CWE-117).
 * - Strips ANSI escapes
 * - Strips control characters (newlines \r, \n, null bytes, backspaces, tabs)
 * - Truncates to maxLength to prevent disk space exhaustion
 *
 * @param val - Untrusted candidate value
 * @param maxLength - Maximum permitted length
 * @returns Sanitized string
 */
export function sanitizeString(val: unknown, maxLength: number = 250): string {
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
 * @param route - Untrusted route string
 * @param maxLength - Maximum permitted length
 * @returns Sanitized route
 */
export function sanitizeRoute(route: unknown, maxLength: number = 500): string {
  if (!route || typeof route !== 'string') {
    return '/';
  }
  let clean = route.split(/[\r\n]/)[0] ?? '';
  clean = stripAnsi(clean);
  // Strip query parameters and URL fragments to prevent credential leakage (CWE-532)
  clean = (clean.split('?')[0] ?? '').split('#')[0] ?? '';
  // Remove dangerous control characters and newlines
  clean = clean.replace(/[\x00-\x1f\x7f]/g, '').trim();
  if (!clean.startsWith('/')) {
    clean = '/' + clean;
  }
  return clean.slice(0, maxLength) || '/';
}

/**
 * Sanitizes HTTP methods.
 * @param method - Untrusted method string
 * @returns Sanitized uppercase HTTP method
 */
export function sanitizeMethod(method: unknown): string {
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
 * - Bounded Queue: Strictly caps pending in-memory write operations to prevent memory exhaustion under attack.
 * - Resilient: Filesystem errors (ENOSPC, EACCES) are safely caught and will not crash the host app.
 * - Sequential Queue: Guarantees concurrency safety so simultaneous writes never corrupt files.
 *
 * Hosting Notice:
 * Logs are stored in local persistent storage. If deployed to ephemeral platforms
 * (e.g. basic Heroku dynos, AWS Lambda, or serverless containers without mounted volumes),
 * local log files may be lost upon container restart or redeployment.
 */
export class Logger {
  readonly appName: string;
  readonly logDir: string;
  readonly logFilename: string;
  readonly filePath: string;
  readonly maxLogSizeBytes: number;
  readonly maxLogFiles: number;
  readonly maxQueueSize: number;
  readonly onLogError: ((err: Error, event: Record<string, unknown>) => void) | null;

  private _writeQueue: Promise<void>;
  private _dirEnsured: boolean;
  private _pendingWrites: number;
  private _droppedEvents: number;
  private _currentLogSizeBytes: number;

  /**
   * @param config - Logger options or resolved Z-Shield configuration
   */
  constructor(config: LoggerOptions | ZShieldConfig | ZShieldOptions = {}) {
    this.appName = config.appName || 'default-app';
    this.logDir = path.resolve(config.logDir || path.join(process.cwd(), '.z-shield-logs'));
    this.logFilename = config.logFilename || 'events.jsonl';
    this.filePath = path.join(this.logDir, this.logFilename);
    this.maxLogSizeBytes = config.maxLogSizeBytes || 5 * 1024 * 1024; // 5MB
    this.maxLogFiles = typeof config.maxLogFiles === 'number' ? config.maxLogFiles : 5;
    const rawQueueLimit =
      (config as Record<string, unknown>).maxLogQueueSize ??
      (config as Record<string, unknown>).maxQueueSize;
    this.maxQueueSize =
      typeof rawQueueLimit === 'number' && Number.isInteger(rawQueueLimit) && rawQueueLimit > 0
        ? rawQueueLimit
        : 1000;
    this.onLogError = typeof config.onLogError === 'function' ? config.onLogError : null;

    this._writeQueue = Promise.resolve();
    this._dirEnsured = false;
    this._pendingWrites = 0;
    this._droppedEvents = 0;
    this._currentLogSizeBytes = -1;
  }

  /**
   * Returns the count of currently queued or executing asynchronous write operations.
   */
  get pendingWrites(): number {
    return this._pendingWrites;
  }

  /**
   * Returns the cumulative count of log events dropped due to write queue overload.
   */
  get droppedEvents(): number {
    return this._droppedEvents;
  }

  /**
   * Formats and sanitizes a security event into a validated schema.
   * Deliberately omits request bodies, authorization headers, cookies, and tokens.
   *
   * @param rawEvent - Raw event object
   * @returns Validated security event
   */
  formatEvent(rawEvent: Record<string, unknown> = {}): FormattedSecurityEvent {
    const rawTimestamp = rawEvent.timestamp;
    const now = typeof rawTimestamp === 'string' || typeof rawTimestamp === 'number'
      ? new Date(rawTimestamp)
      : new Date();
    const timestamp = isNaN(now.getTime()) ? new Date().toISOString() : now.toISOString();

    const allowedSeverities = ['info', 'warning', 'critical'];
    const rawSeverity = typeof rawEvent.severity === 'string' ? rawEvent.severity : '';
    const severity = allowedSeverities.includes(rawSeverity) ? rawSeverity : 'warning';

    const allowedActions = ['blocked', 'warned', 'allowed', 'unblocked'];
    const rawAction = typeof rawEvent.action === 'string' ? rawEvent.action : '';
    const action = allowedActions.includes(rawAction) ? rawAction : 'warned';

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
   * Resolves to true if write succeeded, or false if it failed or was dropped due to queue overload.
   *
   * @param rawEvent - Raw event data
   * @returns True if write succeeded, false otherwise
   */
  log(rawEvent: Record<string, unknown>): Promise<boolean> {
    if (this._pendingWrites >= this.maxQueueSize) {
      this._droppedEvents++;
      if (this.onLogError) {
        try {
          this.onLogError(
            new Error(`[Z-Shield Logger]: Write queue capacity of ${this.maxQueueSize} reached. Event dropped.`),
            rawEvent
          );
        } catch {
          // Prevent user callback exceptions from propagating or crashing
        }
      } else if (this._droppedEvents === 1 || this._droppedEvents % 1000 === 0) {
        console.error(
          `[Z-Shield Logger Warning]: Write queue capacity of ${this.maxQueueSize} reached. ${this._droppedEvents} event(s) dropped.`
        );
      }
      return Promise.resolve(false);
    }

    this._pendingWrites++;
    return new Promise((resolve) => {
      this._writeQueue = this._writeQueue
        .then(() => this._writeEvent(rawEvent))
        .then(() => {
          this._pendingWrites--;
          resolve(true);
        })
        .catch((err: Error) => {
          this._pendingWrites--;
          this._handleError(err, rawEvent);
          resolve(false);
        });
    });
  }

  /**
   * Waits for all currently queued asynchronous log writes to complete.
   * Useful for deterministic testing, graceful shutdowns, and process exit handlers.
   */
  async flush(): Promise<void> {
    await this._writeQueue;
  }

  /**
   * Internal write operation executed within the sequential queue.
   *
   * @param rawEvent - Raw event to serialize and write
   */
  private async _writeEvent(rawEvent: Record<string, unknown>): Promise<void> {
    const event = this.formatEvent(rawEvent);
    await this._ensureDir();
    await this._rotateIfNeeded();

    const line = JSON.stringify(event) + '\n';
    const lineBytes = Buffer.byteLength(line, 'utf8');

    try {
      await fs.promises.appendFile(this.filePath, line, { encoding: 'utf8', flag: 'a' });
      this._currentLogSizeBytes += lineBytes;
    } catch (err: unknown) {
      // Self-healing recovery: if directory was removed externally right before write,
      // recreate directory and retry appending once before throwing.
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        this._dirEnsured = false;
        await fs.promises.mkdir(this.logDir, { recursive: true });
        this._dirEnsured = true;
        await fs.promises.appendFile(this.filePath, line, { encoding: 'utf8', flag: 'a' });
        this._currentLogSizeBytes = lineBytes;
        return;
      }
      this._currentLogSizeBytes = -1;
      throw err;
    }
  }

  /**
   * Ensures the target log directory exists.
   */
  private async _ensureDir(): Promise<void> {
    if (!this._dirEnsured || !fs.existsSync(this.logDir)) {
      await fs.promises.mkdir(this.logDir, { recursive: true });
      this._dirEnsured = true;
    }
  }

  /**
   * Checks file size and rotates log files if size exceeds maxLogSizeBytes.
   * Uses cached in-memory size to avoid expensive disk stat operations on every single write.
   */
  private async _rotateIfNeeded(): Promise<void> {
    // If file size is not yet cached in memory (startup or recovery), stat once.
    if (this._currentLogSizeBytes < 0) {
      try {
        const stats = await fs.promises.stat(this.filePath);
        this._currentLogSizeBytes = stats.size;
      } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
          this._currentLogSizeBytes = 0;
          return; // File does not exist yet
        }
        throw err;
      }
    }

    if (this._currentLogSizeBytes < this.maxLogSizeBytes) {
      return;
    }

    const { name, ext } = path.parse(this.logFilename);

    // If maxLogFiles is 0, simply remove the current file
    if (this.maxLogFiles === 0) {
      try {
        await fs.promises.unlink(this.filePath);
      } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      }
      this._currentLogSizeBytes = 0;
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
        } catch (err: unknown) {
          if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        }
      } else {
        const nextRotated = path.join(this.logDir, `${name}.${i + 1}${ext}`);
        try {
          await fs.promises.rename(currentRotated, nextRotated);
        } catch (err: unknown) {
          if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        }
      }
    }

    // Move current events.jsonl to events.1.jsonl
    const firstRotated = path.join(this.logDir, `${name}.1${ext}`);
    try {
      await fs.promises.rename(this.filePath, firstRotated);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }

    // Reset in-memory size counter after rotation since new file will start fresh
    this._currentLogSizeBytes = 0;
  }

  /**
   * Safely handles write and filesystem failures without crashing the application.
   *
   * @param err - Encountered error
   * @param rawEvent - Raw event data attempted to be written
   */
  private _handleError(err: Error, rawEvent: Record<string, unknown>): void {
    // If the directory was deleted externally while running, reset _dirEnsured so the next
    // write attempt will automatically recreate the directory instead of failing permanently.
    this._dirEnsured = false;
    this._currentLogSizeBytes = -1;

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
