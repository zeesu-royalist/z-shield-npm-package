'use strict';

const path = require('node:path');

/**
 * Default configuration values for Z-Shield.
 * Designed with conservative, safe defaults.
 */
const DEFAULT_CONFIG = {
  // Unique identifier for the host application (useful when multiple apps share a server)
  appName: 'default-app',

  // Mode: 'monitor' (detect and log only) or 'protect' (enforce 429 and temporary blocks)
  mode: 'monitor',

  // Time window for tracking requests in milliseconds (default: 60,000ms = 1 minute)
  windowMs: 60 * 1000,

  // Maximum allowed requests from a single IP within the windowMs
  maxRequests: 100,

  // Directory where JSONL security event logs will be stored
  logDir: path.join(process.cwd(), '.z-shield-logs'),

  // Whether to trust reverse-proxy IP headers (e.g., X-Forwarded-For)
  // CRITICAL: Must be false by default to prevent client IP spoofing attacks
  trustProxy: false,

  // Array of route prefixes that bypass abuse tracking (e.g. internal health checks)
  excludeRoutes: ['/health', '/favicon.ico'],

  // Maximum number of distinct client IPs to track in memory simultaneously
  // Protects against Memory Exhaustion DoS attacks
  maxTrackedIps: 10000,

  // Duration in milliseconds for temporary IP blocks (default: 15 minutes)
  blockDurationMs: 15 * 60 * 1000,

  // Maximum number of blocked IPs to keep in memory simultaneously
  maxBlockedIps: 5000,

  // Whether exceeding rate limit in protect mode automatically triggers a temporary block
  autoBlock: false,

  // Filename for the active JSON Lines log file
  logFilename: 'events.jsonl',

  // Maximum size in bytes before rotating the log file (default: 5MB)
  maxLogSizeBytes: 5 * 1024 * 1024,

  // Maximum number of rotated log files to retain
  maxLogFiles: 5,

  // Optional custom error callback: (err, event) => void
  onLogError: null
};

/**
 * Validates user-provided options and merges them with defaults.
 * Throws clear, helpful errors if an invalid option is passed.
 *
 * @param {Object} [userConfig={}] - Custom configuration provided by the developer
 * @returns {Readonly<Object>} Validated and frozen configuration object
 */
function resolveConfig(userConfig = {}) {
  if (userConfig === null || typeof userConfig !== 'object' || Array.isArray(userConfig)) {
    throw new TypeError('[Z-Shield] Configuration must be a plain object.');
  }

  const config = { ...DEFAULT_CONFIG, ...userConfig };

  // Validate appName
  if (typeof config.appName !== 'string' || config.appName.trim().length === 0) {
    throw new TypeError('[Z-Shield] "appName" must be a non-empty string.');
  }
  // Prevent directory traversal characters in appName (e.g., "../hacker")
  if (!/^[a-zA-Z0-9_-]+$/.test(config.appName)) {
    throw new Error('[Z-Shield] "appName" can only contain letters, numbers, dashes, and underscores.');
  }

  // Validate mode
  if (config.mode !== 'monitor' && config.mode !== 'protect') {
    throw new Error(`[Z-Shield] Invalid mode "${config.mode}". Mode must be either "monitor" or "protect".`);
  }

  // Validate windowMs
  if (typeof config.windowMs !== 'number' || !Number.isFinite(config.windowMs) || config.windowMs <= 0) {
    throw new TypeError('[Z-Shield] "windowMs" must be a positive number in milliseconds.');
  }

  // Validate maxRequests
  if (typeof config.maxRequests !== 'number' || !Number.isInteger(config.maxRequests) || config.maxRequests <= 0) {
    throw new TypeError('[Z-Shield] "maxRequests" must be a positive integer.');
  }

  // Validate logDir
  if (typeof config.logDir !== 'string' || config.logDir.trim().length === 0) {
    throw new TypeError('[Z-Shield] "logDir" must be a non-empty string path.');
  }

  // Validate trustProxy
  if (typeof config.trustProxy !== 'boolean') {
    throw new TypeError('[Z-Shield] "trustProxy" must be a boolean (true or false).');
  }

  // Validate excludeRoutes
  if (!Array.isArray(config.excludeRoutes) || !config.excludeRoutes.every(r => typeof r === 'string')) {
    throw new TypeError('[Z-Shield] "excludeRoutes" must be an array of string route prefixes.');
  }

  // Validate maxTrackedIps
  if (typeof config.maxTrackedIps !== 'number' || !Number.isInteger(config.maxTrackedIps) || config.maxTrackedIps <= 0) {
    throw new TypeError('[Z-Shield] "maxTrackedIps" must be a positive integer.');
  }

  // Validate blockDurationMs
  if (typeof config.blockDurationMs !== 'number' || !Number.isFinite(config.blockDurationMs) || config.blockDurationMs <= 0) {
    throw new TypeError('[Z-Shield] "blockDurationMs" must be a positive number in milliseconds.');
  }

  // Validate maxBlockedIps
  if (typeof config.maxBlockedIps !== 'number' || !Number.isInteger(config.maxBlockedIps) || config.maxBlockedIps <= 0) {
    throw new TypeError('[Z-Shield] "maxBlockedIps" must be a positive integer.');
  }

  // Validate autoBlock
  if (typeof config.autoBlock !== 'boolean') {
    throw new TypeError('[Z-Shield] "autoBlock" must be a boolean (true or false).');
  }

  // Validate logFilename
  if (typeof config.logFilename !== 'string' || config.logFilename.trim().length === 0) {
    throw new TypeError('[Z-Shield] "logFilename" must be a non-empty string.');
  }
  if (!/^[a-zA-Z0-9._-]+$/.test(config.logFilename) || config.logFilename.includes('..')) {
    throw new Error('[Z-Shield] "logFilename" must be a safe filename without path traversal characters.');
  }

  // Validate maxLogSizeBytes
  if (typeof config.maxLogSizeBytes !== 'number' || !Number.isInteger(config.maxLogSizeBytes) || config.maxLogSizeBytes <= 0) {
    throw new TypeError('[Z-Shield] "maxLogSizeBytes" must be a positive integer.');
  }

  // Validate maxLogFiles
  if (typeof config.maxLogFiles !== 'number' || !Number.isInteger(config.maxLogFiles) || config.maxLogFiles < 0) {
    throw new TypeError('[Z-Shield] "maxLogFiles" must be a non-negative integer.');
  }

  // Validate onLogError
  if (config.onLogError !== null && typeof config.onLogError !== 'function') {
    throw new TypeError('[Z-Shield] "onLogError" must be null or a function.');
  }

  // Freeze the object so application code cannot accidentally mutate it at runtime
  return Object.freeze({
    ...config,
    excludeRoutes: Object.freeze([...config.excludeRoutes])
  });
}

module.exports = {
  DEFAULT_CONFIG,
  resolveConfig
};
