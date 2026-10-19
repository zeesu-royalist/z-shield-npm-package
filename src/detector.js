'use strict';

/**
 * Detector - Evaluates incoming requests and detects abuse patterns.
 *
 * In Phase 2, this evaluates whether a client IP has exceeded the
 * maximum request threshold within the configured time window.
 */
class Detector {
  /**
   * @param {Object} options
   * @param {import('./rate-limiter').RateLimiter} options.rateLimiter - The rate-limiter instance
   * @param {Object} options.config - The resolved Z-Shield configuration
   */
  constructor({ rateLimiter, config }) {
    if (!rateLimiter) {
      throw new TypeError('[Z-Shield] Detector requires a RateLimiter instance.');
    }
    if (!config) {
      throw new TypeError('[Z-Shield] Detector requires a resolved config object.');
    }

    this.rateLimiter = rateLimiter;
    this.config = config;
  }

  /**
   * Checks an incoming request against detection rules.
   *
   * @param {string} ip - Client IP address
   * @param {import('express').Request} [req={}] - Express request object
   * @param {number} [now=Date.now()] - Timestamp
   * @returns {Object} Detection evaluation result
   */
  check(ip, req = {}, now = Date.now()) {
    const status = this.rateLimiter.record(ip, now);

    if (status.isExceeded) {
      const windowSeconds = Math.round(this.config.windowMs / 1000);
      return {
        isSuspicious: true,
        type: 'rate_limit',
        severity: 'warning',
        reason: `Request threshold exceeded (${status.count}/${this.config.maxRequests} in ${windowSeconds}s)`,
        count: status.count,
        maxRequests: this.config.maxRequests,
        remaining: status.remaining,
        resetTime: status.resetTime,
        timestamp: new Date(now).toISOString()
      };
    }

    return {
      isSuspicious: false,
      type: 'normal',
      severity: 'info',
      reason: null,
      count: status.count,
      maxRequests: this.config.maxRequests,
      remaining: status.remaining,
      resetTime: status.resetTime,
      timestamp: new Date(now).toISOString()
    };
  }

  /**
   * Inspects current status without incrementing counters.
   *
   * @param {string} ip
   * @param {number} [now=Date.now()]
   * @returns {Object}
   */
  inspect(ip, now = Date.now()) {
    const status = this.rateLimiter.get(ip, now);

    return {
      isSuspicious: status.isExceeded,
      count: status.count,
      maxRequests: this.config.maxRequests,
      remaining: status.remaining,
      resetTime: status.resetTime
    };
  }
}

module.exports = {
  Detector
};
