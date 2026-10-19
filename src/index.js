'use strict';

const { createMiddleware } = require('./middleware');
const { resolveConfig, DEFAULT_CONFIG } = require('./config');
const { RateLimiter } = require('./rate-limiter');
const { Detector } = require('./detector');
const { BlockManager } = require('./block-manager');

/**
 * Main factory function for initializing Z-Shield.
 *
 * Usage in Express:
 *   const { createShield } = require('z-shield');
 *   const shield = createShield({ mode: 'protect', maxRequests: 50 });
 *   app.use(shield.middleware);
 *
 * Programmatic Block API:
 *   shield.block('198.51.100.1', '10m', 'Manual administrative block');
 *   shield.unblock('198.51.100.1');
 *   shield.isBlocked('198.51.100.1');
 *
 * @param {Object} [options={}] - Custom configuration options
 * @returns {Object} Z-Shield instance with middleware, managers, and programmatic methods
 */
function createShield(options = {}) {
  const config = resolveConfig(options);
  const rateLimiter = new RateLimiter(config);
  const detector = new Detector({ rateLimiter, config });
  const blockManager = new BlockManager(config);

  const middleware = createMiddleware(config, {
    rateLimiter,
    detector,
    blockManager
  });

  return {
    middleware,
    config,
    rateLimiter,
    detector,
    blockManager,

    // Programmatic Block API
    block: (ip, duration, reason) => blockManager.block(ip, duration, reason),
    unblock: (ip) => blockManager.unblock(ip),
    isBlocked: (ip) => blockManager.isBlocked(ip),
    getBlockInfo: (ip) => blockManager.getBlockInfo(ip),
    listBlocks: () => blockManager.listBlocks()
  };
}

module.exports = {
  createShield,
  createMiddleware,
  resolveConfig,
  DEFAULT_CONFIG,
  RateLimiter,
  Detector,
  BlockManager
};
