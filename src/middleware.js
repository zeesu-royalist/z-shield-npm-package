'use strict';

const { resolveConfig } = require('./config');
const { RateLimiter } = require('./rate-limiter');
const { Detector } = require('./detector');
const { BlockManager } = require('./block-manager');
const { Logger } = require('./logger');

/**
 * Safely extracts the client's IP address.
 *
 * Security Note:
 * An attacker can easily send spoofed headers like `X-Forwarded-For: 1.2.3.4`.
 * Therefore, we NEVER inspect `X-Forwarded-For` directly unless `trustProxy` is true
 * AND Express itself has verified it through its own `trust proxy` configuration.
 *
 * @param {import('express').Request} req - The incoming Express request object
 * @param {boolean} trustProxy - Whether proxy headers are explicitly trusted
 * @returns {string} The normalized client IP address
 */
function extractClientIp(req, trustProxy) {
  let ip = '';

  if (trustProxy && typeof req.ip === 'string' && req.ip.length > 0) {
    ip = req.ip;
  } else if (req.socket && typeof req.socket.remoteAddress === 'string') {
    ip = req.socket.remoteAddress;
  } else if (req.connection && typeof req.connection.remoteAddress === 'string') {
    ip = req.connection.remoteAddress;
  }

  // Normalize IPv6-mapped IPv4 addresses (e.g., '::ffff:127.0.0.1' -> '127.0.0.1')
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }

  // Normalize IPv6 localhost loopback ('::1' -> '127.0.0.1' for cleaner developer output)
  if (ip === '::1') {
    ip = '127.0.0.1';
  }

  return ip || 'unknown';
}

/**
 * Factory function to create the Z-Shield Express middleware.
 *
 * @param {Object} [options={}] - Custom configuration options
 * @param {Object} [dependencies={}] - Injected dependencies (useful for testing)
 * @param {RateLimiter} [dependencies.rateLimiter]
 * @param {Detector} [dependencies.detector]
 * @param {BlockManager} [dependencies.blockManager]
 * @param {Logger} [dependencies.logger]
 * @returns {Function} Express middleware function: (req, res, next) => void
 */
function createMiddleware(options = {}, dependencies = {}) {
  const config = resolveConfig(options);
  const rateLimiter = dependencies.rateLimiter || new RateLimiter(config);
  const detector = dependencies.detector || new Detector({ rateLimiter, config });
  const blockManager = dependencies.blockManager || new BlockManager(config);
  const logger = dependencies.logger || new Logger(config);

  return function zShieldMiddleware(req, res, next) {
    try {
      const clientIp = extractClientIp(req, config.trustProxy);
      const requestPath = req.path || req.url || '/';
      const requestMethod = req.method || 'GET';
      const now = Date.now();

      // Check if this route is in the exclusion list (e.g. /health check)
      const isExcluded = config.excludeRoutes.some(prefix => requestPath.startsWith(prefix));

      if (isExcluded) {
        req.zShield = {
          ip: clientIp,
          mode: config.mode,
          appName: config.appName,
          isExcluded: true,
          startTime: now,
          detection: null,
          blocked: false
        };
        res.setHeader('X-Z-Shield-Protected', '1');
        res.setHeader('X-Z-Shield-Mode', config.mode);
        return next();
      }

      // Step 1: Check active temporary blocks
      const isIpBlocked = blockManager.isBlocked(clientIp, now);

      if (isIpBlocked) {
        const blockInfo = blockManager.getBlockInfo(clientIp, now);
        const retryAfterSeconds = Math.max(1, Math.ceil(blockInfo.remainingMs / 1000));
        const action = config.mode === 'protect' ? 'blocked' : 'warned';

        // Log the security event asynchronously
        const logPromise = logger.log({
          appName: config.appName,
          type: 'blocked_ip',
          severity: 'warning',
          ip: clientIp,
          method: requestMethod,
          route: requestPath,
          reason: blockInfo.reason,
          action
        });

        req.zShield = {
          ip: clientIp,
          mode: config.mode,
          appName: config.appName,
          isExcluded: false,
          startTime: now,
          detection: null,
          blocked: true,
          blockReason: blockInfo.reason,
          logPromise
        };

        res.setHeader('X-Z-Shield-Protected', '1');
        res.setHeader('X-Z-Shield-Mode', config.mode);
        res.setHeader('X-Z-Shield-Blocked', '1');
        res.setHeader('X-Z-Shield-Reason', blockInfo.reason);
        res.setHeader('Retry-After', String(retryAfterSeconds));

        if (config.mode === 'protect') {
          return res.status(429).json({
            error: 'Too Many Requests',
            message: 'Your IP address has been temporarily blocked due to suspicious activity.',
            retryAfter: retryAfterSeconds
          });
        }

        // Monitor mode: mark warning header, but allow request through
        res.setHeader('X-Z-Shield-Suspicious', '1');
        return next();
      }

      // Step 2: Rate limit tracking and abuse detection
      const detection = detector.check(clientIp, req, now);

      let logPromise = null;
      if (detection.isSuspicious) {
        const action = config.mode === 'protect' ? 'blocked' : 'warned';
        logPromise = logger.log({
          appName: config.appName,
          type: detection.type || 'rate_limit',
          severity: detection.severity || 'warning',
          ip: clientIp,
          method: requestMethod,
          route: requestPath,
          reason: detection.reason,
          action
        });
      }

      req.zShield = {
        ip: clientIp,
        mode: config.mode,
        appName: config.appName,
        isExcluded: false,
        startTime: now,
        detection,
        blocked: false,
        logPromise
      };

      // Set informative headers
      res.setHeader('X-Z-Shield-Protected', '1');
      res.setHeader('X-Z-Shield-Mode', config.mode);
      res.setHeader('X-RateLimit-Limit', String(config.maxRequests));
      res.setHeader('X-RateLimit-Remaining', String(detection.remaining));
      res.setHeader('X-RateLimit-Reset', String(Math.ceil(detection.resetTime / 1000)));

      if (detection.isSuspicious) {
        res.setHeader('X-Z-Shield-Suspicious', '1');
        res.setHeader('X-Z-Shield-Reason', detection.reason);

        if (config.mode === 'protect') {
          // If autoBlock is enabled, add to block manager
          if (config.autoBlock) {
            blockManager.block(clientIp, config.blockDurationMs, detection.reason, now);
          }

          const retryAfterSeconds = Math.max(1, Math.ceil((detection.resetTime - now) / 1000));
          res.setHeader('Retry-After', String(retryAfterSeconds));

          return res.status(429).json({
            error: 'Too Many Requests',
            message: 'Request threshold exceeded. Please try again later.',
            retryAfter: retryAfterSeconds
          });
        }
      }

      // In monitor mode or normal traffic in protect mode: allow through
      return next();
    } catch (err) {
      // If an unexpected error occurs in middleware execution, pass it safely to Express
      // error handling without crashing the entire Node.js server process.
      return next(err);
    }
  };
}

module.exports = {
  createMiddleware,
  extractClientIp
};
