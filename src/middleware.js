'use strict';

const { resolveConfig } = require('./config');

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

const { RateLimiter } = require('./rate-limiter');
const { Detector } = require('./detector');

/**
 * Factory function to create the Z-Shield Express middleware.
 *
 * @param {Object} [options={}] - Custom configuration options
 * @param {Object} [dependencies={}] - Injected dependencies (useful for testing)
 * @param {RateLimiter} [dependencies.rateLimiter]
 * @param {Detector} [dependencies.detector]
 * @returns {Function} Express middleware function: (req, res, next) => void
 */
function createMiddleware(options = {}, dependencies = {}) {
  const config = resolveConfig(options);
  const rateLimiter = dependencies.rateLimiter || new RateLimiter(config);
  const detector = dependencies.detector || new Detector({ rateLimiter, config });

  return function zShieldMiddleware(req, res, next) {
    try {
      const clientIp = extractClientIp(req, config.trustProxy);
      const requestPath = req.path || req.url || '/';

      // Check if this route is in the exclusion list (e.g. /health check)
      const isExcluded = config.excludeRoutes.some(prefix => requestPath.startsWith(prefix));

      // In Phase 2: Detect abuse if route is not excluded
      let detection = null;
      if (!isExcluded) {
        detection = detector.check(clientIp, req);
      }

      // Attach Z-Shield metadata to the request for logging or downstream route handlers
      req.zShield = {
        ip: clientIp,
        mode: config.mode,
        appName: config.appName,
        isExcluded,
        startTime: Date.now(),
        detection
      };

      // Set standard informative headers so client and developers know Z-Shield is active
      res.setHeader('X-Z-Shield-Protected', '1');
      res.setHeader('X-Z-Shield-Mode', config.mode);

      // Expose standard rate limit headers when tracking is active
      if (detection) {
        res.setHeader('X-RateLimit-Limit', String(config.maxRequests));
        res.setHeader('X-RateLimit-Remaining', String(detection.remaining));
        res.setHeader('X-RateLimit-Reset', String(Math.ceil(detection.resetTime / 1000)));

        // If suspicious (e.g. threshold exceeded), expose warning headers
        if (detection.isSuspicious) {
          res.setHeader('X-Z-Shield-Suspicious', '1');
          res.setHeader('X-Z-Shield-Reason', detection.reason);
        }
      }

      // In Phase 2 (monitor mode), requests are allowed to proceed without blocking
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
