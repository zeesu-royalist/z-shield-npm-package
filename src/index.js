'use strict';

const { createMiddleware } = require('./middleware');
const { resolveConfig, DEFAULT_CONFIG } = require('./config');
const { RateLimiter } = require('./rate-limiter');
const { Detector } = require('./detector');

/**
 * Main factory function for initializing Z-Shield.
 *
 * Usage in Express:
 *   const { createShield } = require('z-shield');
 *   const shield = createShield({ mode: 'monitor', maxRequests: 50 });
 *   app.use(shield.middleware);
 *
 * @param {Object} [options={}] - Custom configuration options
 * @returns {Object} An object containing the Express middleware, config, rateLimiter, and detector
 */
function createShield(options = {}) {
  const config = resolveConfig(options);
  const rateLimiter = new RateLimiter(config);
  const detector = new Detector({ rateLimiter, config });
  const middleware = createMiddleware(config, { rateLimiter, detector });

  return {
    middleware,
    config,
    rateLimiter,
    detector
  };
}

module.exports = {
  createShield,
  createMiddleware,
  resolveConfig,
  DEFAULT_CONFIG,
  RateLimiter,
  Detector
};
