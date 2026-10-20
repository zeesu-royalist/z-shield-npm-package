import { createMiddleware, extractClientIp, isRouteExcluded, safelyEndResponse } from './middleware';
import { createNextShield, withNextShield, extractNextClientIp } from './next';
import { resolveConfig, DEFAULT_CONFIG } from './config';
import { RateLimiter } from './rate-limiter';
import { Detector } from './detector';
import { BlockManager, isValidIp, normalizeIp, parseDuration, type BlockInfo } from './block-manager';
import { Logger, stripAnsi, sanitizeString, sanitizeRoute, sanitizeMethod } from './logger';
import type {
  ZShieldConfig,
  ZShieldOptions,
  BlockRecord,
  ZShieldInstance,
  ZShieldFullInstance
} from './types';

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
 * @param options - Custom configuration options
 * @returns Z-Shield instance with middleware, managers, logger, and programmatic methods
 */
export function createShield(options: ZShieldOptions | ZShieldConfig = {}): ZShieldInstance {
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
    block: (ip: string, duration?: string | number, reason?: string): BlockRecord => {
      const result = blockManager.block(ip, duration, reason);
      void logger.log({
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

    unblock: (ip: string): boolean => {
      const result = blockManager.unblock(ip);
      if (result) {
        void logger.log({
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

    isBlocked: (ip: string): boolean => blockManager.isBlocked(ip),
    getBlockInfo: (ip: string): BlockInfo | null => blockManager.getBlockInfo(ip),
    listBlocks: (): BlockInfo[] => blockManager.listBlocks(),
    flush: (): Promise<void> => logger.flush()
  };
}

export {
  createMiddleware,
  extractClientIp,
  isRouteExcluded,
  safelyEndResponse,
  resolveConfig,
  DEFAULT_CONFIG,
  RateLimiter,
  Detector,
  BlockManager,
  isValidIp,
  normalizeIp,
  parseDuration,
  Logger,
  stripAnsi,
  sanitizeString,
  sanitizeRoute,
  sanitizeMethod,
  createNextShield,
  withNextShield,
  extractNextClientIp
};

export type { BlockInfo, ZShieldInstance, ZShieldFullInstance };
export * from './types';

