'use strict';

const { createMiddleware } = require('./middleware');
const { resolveConfig, DEFAULT_CONFIG } = require('./config');
const { RateLimiter } = require('./rate-limiter');
const { Detector } = require('./detector');
const { BlockManager } = require('./block-manager');
const { Logger } = require('./logger');

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
 * @returns {Object} Z-Shield instance with middleware, managers, logger, and programmatic methods
 */
function createShield(options = {}) {
  const config = resolveConfig(options);
  const rateLimiter = new RateLimiter(config);
  const detector = new Detector({ rateLimiter, config });
  const blockManager = new BlockManager(config);
  const logger = new Logger(config);

  const middleware = createMiddleware(config, {
    rateLimiter,
    detector,
    blockManager,
    logger
  });

  return {
    middleware,
    config,
    rateLimiter,
    detector,
    blockManager,
    logger,

    // Programmatic Block API with security event logging
    block: (ip, duration, reason) => {
      const result = blockManager.block(ip, duration, reason);
      logger.log({
        appName: config.appName,
        type: 'manual_block',
        severity: 'info',
        ip,
        method: 'INTERNAL',
        route: '/admin/block',
        reason: result.reason,
        action: 'blocked'
      });
      return result;
    },

    unblock: (ip) => {
      const result = blockManager.unblock(ip);
      if (result) {
        logger.log({
          appName: config.appName,
          type: 'manual_unblock',
          severity: 'info',
          ip,
          method: 'INTERNAL',
          route: '/admin/unblock',
          reason: 'Manual unblock requested',
          action: 'unblocked'
        });
      }
      return result;
    },

    isBlocked: (ip) => blockManager.isBlocked(ip),
    getBlockInfo: (ip) => blockManager.getBlockInfo(ip),
    listBlocks: () => blockManager.listBlocks(),
    flush: () => logger.flush()
  };
}

module.exports = {
  createShield,
  createMiddleware,
  resolveConfig,
  DEFAULT_CONFIG,
  RateLimiter,
  Detector,
  BlockManager,
  Logger
};
