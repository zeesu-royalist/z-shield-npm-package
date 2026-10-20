import { resolveConfig } from './config';
import { RateLimiter } from './rate-limiter';
import { Detector } from './detector';
import { BlockManager, isValidIp, normalizeIp } from './block-manager';
import { Logger } from './logger';
import type {
  ExpressLikeRequest,
  ExpressLikeResponse,
  ExpressLikeNextFunction,
  ExpressMiddleware,
  ZShieldConfig,
  ZShieldOptions
} from './types';

declare global {
  namespace Express {
    interface Request {
      zShield?: {
        ip: string;
        mode: string;
        appName: string;
        isExcluded: boolean;
        startTime: number;
        detection: unknown;
        blocked: boolean;
        blockReason?: string;
        logPromise?: Promise<boolean> | null;
      };
    }
  }
}

export interface MiddlewareDependencies {
  rateLimiter?: RateLimiter;
  detector?: Detector;
  blockManager?: BlockManager;
  logger?: Logger;
}

interface LegacyConnectionHolder {
  connection?: {
    remoteAddress?: string;
  };
}

function hasLegacyConnection(req: unknown): req is LegacyConnectionHolder {
  return (
    typeof req === 'object' &&
    req !== null &&
    'connection' in req &&
    typeof (req as LegacyConnectionHolder).connection === 'object' &&
    (req as LegacyConnectionHolder).connection !== null
  );
}

/**
 * Safely extracts the client's IP address and normalizes IPv4 and IPv6 representations.
 *
 * Security Note:
 * An attacker can easily send spoofed headers like `X-Forwarded-For: 1.2.3.4`.
 * Therefore, we NEVER inspect `X-Forwarded-For` directly unless `trustProxy` is true
 * AND Express itself has verified it through its own `trust proxy` configuration.
 *
 * @param req - The incoming Express request object
 * @param trustProxy - Whether proxy headers are explicitly trusted
 * @returns The normalized client IP address
 */
export function extractClientIp(req: ExpressLikeRequest, trustProxy: boolean): string {
  let ip = '';

  if (trustProxy && typeof req.ip === 'string' && req.ip.length > 0) {
    ip = req.ip;
  } else if (req.socket && typeof req.socket.remoteAddress === 'string') {
    ip = req.socket.remoteAddress;
  } else if (hasLegacyConnection(req) && typeof req.connection?.remoteAddress === 'string') {
    ip = req.connection.remoteAddress;
  }

  return normalizeIp(ip);
}

/**
 * Determines whether a given request path matches any of the excluded route patterns.
 * Respects path-segment boundaries so that excluding '/health' matches '/health' or '/health/live'
 * but does NOT match '/health-admin' or '/healthcare'.
 * Also normalizes trailing slashes and ignores query strings and fragments.
 *
 * @param requestPath - The incoming request path (or raw url)
 * @param excludeRoutes - Configured excluded route prefixes
 * @returns True if route is excluded
 */
export function isRouteExcluded(requestPath: string, excludeRoutes: readonly string[]): boolean {
  if (!Array.isArray(excludeRoutes) || excludeRoutes.length === 0) {
    return false;
  }

  // Strip query string and fragment if present (e.g. from req.url)
  const cleanPath = (requestPath || '/').split('?')[0].split('#')[0];

  return excludeRoutes.some((route) => {
    if (typeof route !== 'string' || route.length === 0) {
      return false;
    }

    if (route === '/') {
      return cleanPath === '/';
    }

    // Strip trailing slash from route prefix for normalized segment comparison
    const normalizedPrefix = route.endsWith('/') ? route.slice(0, -1) : route;

    // Exact match (e.g. '/health' === '/health' or '/status' === '/status')
    if (cleanPath === normalizedPrefix) {
      return true;
    }

    // Sub-path segment match (e.g. '/health/check'.startsWith('/health/'))
    if (cleanPath.startsWith(normalizedPrefix + '/')) {
      return true;
    }

    return false;
  });
}

/**
 * Sets a response header only if headers have not already been sent to the client.
 *
 * @param res - Response object
 * @param name - Header name
 * @param value - Header value
 */
function safeSetHeader(res: ExpressLikeResponse, name: string, value: string): void {
  if (res && !res.headersSent && typeof res.setHeader === 'function') {
    res.setHeader(name, value);
  }
}

/**
 * Safely terminates an open HTTP response without calling next() or setting headers.
 * Used when a blocked request in protect mode already had its headers committed upstream.
 *
 * @param res - Response object
 */
export function safelyEndResponse(res: ExpressLikeResponse): void {
  if (res && !res.writableEnded && typeof res.end === 'function') {
    res.end();
  }
}

/**
 * Factory function to create the Z-Shield Express middleware.
 *
 * @param options - Custom configuration options
 * @param dependencies - Injected dependencies (useful for testing)
 * @returns Express middleware function: (req, res, next) => void
 */
export function createMiddleware(
  options: ZShieldOptions | ZShieldConfig = {},
  dependencies: MiddlewareDependencies = {}
): ExpressMiddleware {
  const config = resolveConfig(options);
  const rateLimiter = dependencies.rateLimiter || new RateLimiter(config);
  const detector = dependencies.detector || new Detector({ rateLimiter, config });
  const blockManager = dependencies.blockManager || new BlockManager(config);
  const logger = dependencies.logger || new Logger(config);

  return function zShieldMiddleware(
    req: ExpressLikeRequest,
    res: ExpressLikeResponse,
    next: ExpressLikeNextFunction
  ): void {
    try {
      const clientIp = extractClientIp(req, config.trustProxy);
      const rawPath = (typeof req.path === 'string' && req.path.length > 0)
        ? req.path
        : (req.url || '/');
      const requestPath = rawPath.split('?')[0].split('#')[0] || '/';
      const requestMethod = req.method || 'GET';
      const now = Date.now();

      // Check if this route is in the exclusion list (respecting segment boundaries)
      const isExcluded = isRouteExcluded(requestPath, config.excludeRoutes);

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
        safeSetHeader(res, 'X-Z-Shield-Protected', '1');
        safeSetHeader(res, 'X-Z-Shield-Mode', config.mode);
        return next();
      }

      // Step 1: Check active temporary blocks
      const isIpBlocked = blockManager.isBlocked(clientIp, now);

      if (isIpBlocked) {
        const blockInfo = blockManager.getBlockInfo(clientIp, now);
        const reason = blockInfo ? blockInfo.reason : 'Administrative block';
        const remainingMs = blockInfo ? blockInfo.remainingMs : 0;
        const retryAfterSeconds = Math.max(1, Math.ceil(remainingMs / 1000));
        const action = config.mode === 'protect' ? 'blocked' : 'warned';

        // Log the security event asynchronously
        const logPromise = logger.log({
          appName: config.appName,
          type: 'blocked_ip',
          severity: 'warning',
          ip: clientIp,
          method: requestMethod,
          route: requestPath,
          reason,
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
          blockReason: reason,
          logPromise
        };

        safeSetHeader(res, 'X-Z-Shield-Protected', '1');
        safeSetHeader(res, 'X-Z-Shield-Mode', config.mode);
        safeSetHeader(res, 'X-Z-Shield-Blocked', '1');
        safeSetHeader(res, 'X-Z-Shield-Reason', reason);
        safeSetHeader(res, 'Retry-After', String(retryAfterSeconds));

        if (config.mode === 'protect') {
          if (!res.headersSent) {
            if (typeof res.status === 'function') {
              const statusRes = res.status(429);
              if (statusRes && typeof statusRes.json === 'function') {
                statusRes.json({
                  error: 'Too Many Requests',
                  message: 'Your IP address has been temporarily blocked due to suspicious activity.',
                  retryAfter: retryAfterSeconds
                });
                return;
              }
            }
          }
          // If headers were already committed upstream, we cannot send 429.
          // Safely terminate the open response without calling next().
          safelyEndResponse(res);
          return;
        }

        // Monitor mode: mark warning header, but allow request through
        safeSetHeader(res, 'X-Z-Shield-Suspicious', '1');
        return next();
      }

      // Step 2: Rate limit tracking and abuse detection
      const detection = detector.check(clientIp, req, now);

      let logPromise: Promise<boolean> | null = null;
      if (detection.isSuspicious) {
        const action = config.mode === 'protect' ? 'blocked' : 'warned';
        logPromise = logger.log({
          appName: config.appName,
          type: detection.type || 'rate_limit',
          severity: detection.severity || 'warning',
          ip: clientIp,
          method: requestMethod,
          route: requestPath,
          reason: detection.reason || 'Threshold exceeded',
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
      safeSetHeader(res, 'X-Z-Shield-Protected', '1');
      safeSetHeader(res, 'X-Z-Shield-Mode', config.mode);
      safeSetHeader(res, 'X-RateLimit-Limit', String(config.maxRequests));
      safeSetHeader(res, 'X-RateLimit-Remaining', String(detection.remaining));
      safeSetHeader(res, 'X-RateLimit-Reset', String(Math.ceil(detection.resetTime / 1000)));

      if (detection.isSuspicious) {
        safeSetHeader(res, 'X-Z-Shield-Suspicious', '1');
        safeSetHeader(res, 'X-Z-Shield-Reason', detection.reason || 'Threshold exceeded');

        if (config.mode === 'protect') {
          // If autoBlock is enabled and IP is valid, add to block manager.
          // Unknown or invalid IPs must not be passed to blockManager.block()
          // as that would throw a TypeError and cause an unexpected HTTP 500.
          if (config.autoBlock && isValidIp(clientIp)) {
            blockManager.block(clientIp, config.blockDurationMs, detection.reason || 'Threshold exceeded', now);
          }

          const retryAfterSeconds = Math.max(1, Math.ceil((detection.resetTime - now) / 1000));
          safeSetHeader(res, 'Retry-After', String(retryAfterSeconds));

          if (!res.headersSent) {
            if (typeof res.status === 'function') {
              const statusRes = res.status(429);
              if (statusRes && typeof statusRes.json === 'function') {
                statusRes.json({
                  error: 'Too Many Requests',
                  message: 'Request threshold exceeded. Please try again later.',
                  retryAfter: retryAfterSeconds
                });
                return;
              }
            }
          }
          // If headers were already committed upstream, we cannot send 429.
          // Safely terminate the open response without calling next().
          safelyEndResponse(res);
          return;
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

