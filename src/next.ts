/**
 * Next.js App Router Compatibility Adapter for Z-Shield.
 *
 * Provides Web-standard Request and Response security middleware for Next.js App Router
 * route handlers (e.g. app/api/.../route.ts).
 *
 * Runtime requirement: Node.js runtime (`export const runtime = 'nodejs';`).
 * State note: In-memory rate limiting and blocking state is process-local.
 */

import { resolveConfig } from './config';
import { RateLimiter } from './rate-limiter';
import { Detector } from './detector';
import { BlockManager, isValidIp, normalizeIp, type BlockInfo } from './block-manager';
import { Logger } from './logger';
import { isRouteExcluded } from './middleware';
import type {
  ZShieldConfig,
  BlockRecord,
  ZShieldInstance,
  NextLikeRequest,
  NextShieldOptions,
  NextShieldCheckResult,
  NextShieldInstance,
  NextClientIpStrategy,
  NextClientIpExtractor
} from './types';

/**
 * Reads a header value from standard Headers or a plain object map.
 */
function getHeader(request: Request | NextLikeRequest, name: string): string | null {
  if (!request || !request.headers) {
    return null;
  }
  if (typeof (request.headers as Headers).get === 'function') {
    return (request.headers as Headers).get(name);
  }
  const headersObj = request.headers as Record<string, string | string[] | undefined>;
  const val = headersObj[name] ?? headersObj[name.toLowerCase()];
  if (Array.isArray(val)) {
    return val[0] ?? null;
  }
  return typeof val === 'string' ? val : null;
}

/**
 * Extracts and normalizes the client IP address from a Web-standard or Next.js Request.
 *
 * Security Model:
 * 1. When `trustProxy` is false:
 *    - All reverse-proxy headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP, etc.)
 *      and unverified platform properties are strictly ignored to prevent client IP spoofing attacks.
 *    - Only a verified Node.js TCP socket remote address (`socket.remoteAddress`) or an
 *      explicitly provided custom extractor function is accepted.
 *    - In environments without a direct TCP socket (e.g. serverless Web Requests without a trusted proxy),
 *      safe client IP identification cannot be guaranteed, and this function safely falls back to 'unknown'.
 *
 * 2. When `trustProxy` is true:
 *    - To prevent forged header injection across reverse proxies (e.g. an attacker sending CF-Connecting-IP
 *      to an Nginx server that does not strip it), Z-Shield strictly requires selecting an explicit trusted
 *      strategy via `getIp` or providing a custom extraction callback:
 *      - 'cloudflare' | 'cf-connecting-ip': Trusts only the CF-Connecting-IP header.
 *      - 'nginx' | 'x-real-ip': Trusts only the X-Real-IP header.
 *      - 'akamai' | 'true-client-ip': Trusts only the True-Client-IP header.
 *      - 'x-forwarded-for': Trusts the first valid IP in X-Forwarded-For (requires outer proxy header stripping).
 *      - Custom function: `(req) => string | null | undefined`
 *    - If `trustProxy` is true but no extraction strategy or custom function is configured,
 *      Z-Shield strictly refuses to guess across foreign proxy headers, and falls back safely to 'unknown'
 *      (or socket.remoteAddress if available).
 *
 * @param request - Incoming Web Request or NextLikeRequest
 * @param trustProxy - Whether reverse proxy headers are trusted
 * @param extractorOrStrategy - Trusted IP strategy name or custom extractor function
 * @returns Normalized client IP address or 'unknown'
 */
export function extractNextClientIp(
  request: Request | NextLikeRequest,
  trustProxy: boolean,
  extractorOrStrategy?: NextClientIpExtractor | NextClientIpStrategy
): string {
  // 1. Custom extractor callback function takes precedence if provided by developer
  if (typeof extractorOrStrategy === 'function') {
    try {
      const customIp = extractorOrStrategy(request);
      if (typeof customIp === 'string' && customIp.trim().length > 0) {
        const trimmed = customIp.trim();
        if (isValidIp(trimmed)) {
          return normalizeIp(trimmed);
        }
      }
    } catch {
      // Gracefully fall through on extractor errors
    }
    return 'unknown';
  }

  const reqWithIp = request as { ip?: unknown; socket?: { remoteAddress?: unknown } };

  // 2. When trustProxy is false:
  // Strictly ignore all reverse-proxy headers (X-Forwarded-For, X-Real-IP, etc.)
  // and unverified platform headers to prevent client IP spoofing attacks.
  if (!trustProxy) {
    if (typeof reqWithIp.socket?.remoteAddress === 'string' && reqWithIp.socket.remoteAddress.length > 0) {
      return normalizeIp(reqWithIp.socket.remoteAddress);
    }
    // If no direct TCP socket is available (e.g. serverless Web Request without trusted proxy),
    // safe client IP identification cannot be guaranteed. Fallback to 'unknown'.
    return 'unknown';
  }

  // 3. When trustProxy is true:
  // An explicit trusted IP extraction strategy must be selected.
  // Z-Shield strictly refuses to guess across foreign proxy headers to prevent
  // forged header injection attacks (e.g. sending CF-Connecting-IP to an Nginx server).
  if (typeof extractorOrStrategy === 'string') {
    const strategy = extractorOrStrategy.toLowerCase().trim();

    if (strategy === 'cf-connecting-ip' || strategy === 'cloudflare') {
      const cfIp = getHeader(request, 'cf-connecting-ip');
      if (cfIp) {
        const candidate = cfIp.trim();
        if (isValidIp(candidate)) {
          return normalizeIp(candidate);
        }
      }
      return 'unknown';
    }

    if (strategy === 'x-real-ip' || strategy === 'nginx') {
      const xRealIp = getHeader(request, 'x-real-ip');
      if (xRealIp) {
        const candidate = xRealIp.trim();
        if (isValidIp(candidate)) {
          return normalizeIp(candidate);
        }
      }
      return 'unknown';
    }

    if (strategy === 'true-client-ip' || strategy === 'akamai') {
      const trueIp = getHeader(request, 'true-client-ip');
      if (trueIp) {
        const candidate = trueIp.trim();
        if (isValidIp(candidate)) {
          return normalizeIp(candidate);
        }
      }
      return 'unknown';
    }

    if (strategy === 'x-forwarded-for') {
      const xff = getHeader(request, 'x-forwarded-for');
      if (xff) {
        const candidates = xff.split(',').map(s => s.trim()).filter(Boolean);
        for (const candidate of candidates) {
          if (isValidIp(candidate)) {
            return normalizeIp(candidate);
          }
        }
      }
      return 'unknown';
    }
  }

  // 4. Fallback if no strategy matched or no proxy header was trusted:
  // If a direct TCP socket is available, return it; otherwise fail safely to 'unknown'.
  if (typeof reqWithIp.socket?.remoteAddress === 'string' && reqWithIp.socket.remoteAddress.length > 0) {
    return normalizeIp(reqWithIp.socket.remoteAddress);
  }

  return 'unknown';
}

/**
 * Extracts pathname from a request URL safely.
 */
function extractRequestPath(request: Request | NextLikeRequest): string {
  if (!request.url) {
    return '/';
  }
  try {
    const parsed = new URL(request.url, 'http://localhost');
    return parsed.pathname;
  } catch {
    return request.url.split('?')[0].split('#')[0] || '/';
  }
}

/**
 * Merges rate-limiting headers into an existing Web Response.
 */
function mergeResponseHeaders(
  response: Response,
  headersToMerge: Record<string, string>
): Response {
  if (!response) {
    return response;
  }

  try {
    for (const [key, value] of Object.entries(headersToMerge)) {
      response.headers.set(key, value);
    }
    return response;
  } catch {
    const newHeaders = new Headers(response.headers);
    for (const [key, value] of Object.entries(headersToMerge)) {
      newHeaders.set(key, value);
    }

    const body =
      response.status === 204 || response.status === 205 || response.status === 304
        ? null
        : response.body;

    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  }
}

/**
 * Creates standard HTTP 429 response when a request is blocked.
 */
function createBlockedResponse(
  retryAfter: number,
  reason: string,
  extraHeaders?: Record<string, string>,
  customBuilder?: (info: { reason: string; retryAfter: number; clientIp: string }) => Response,
  clientIp?: string
): Response {
  if (typeof customBuilder === 'function') {
    try {
      return customBuilder({
        reason,
        retryAfter,
        clientIp: clientIp || 'unknown'
      });
    } catch {
      // Fallback to standard response if custom builder throws
    }
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Retry-After': String(retryAfter),
    'X-Z-Shield-Blocked': '1',
    ...extraHeaders
  };

  const body = {
    error: 'Too Many Requests',
    message: reason,
    retryAfter
  };

  return new Response(JSON.stringify(body), {
    status: 429,
    headers
  });
}

/**
 * Checks if the passed object is an existing ZShieldInstance.
 */
function isZShieldInstance(val: unknown): val is ZShieldInstance {
  return (
    typeof val === 'object' &&
    val !== null &&
    'rateLimiter' in val &&
    'detector' in val &&
    'blockManager' in val &&
    'logger' in val &&
    'config' in val
  );
}

/**
 * Factory for creating a Next.js App Router shield instance.
 *
 * Usage:
 *   import { createNextShield } from 'z-shield';
 *   const shield = createNextShield({ mode: 'protect', maxRequests: 50 });
 *
 *   export const GET = shield.protect(async (request) => {
 *     return Response.json({ message: 'Hello from protected API' });
 *   });
 *
 * @param optionsOrInstance - Configuration options or existing ZShieldInstance
 * @returns NextShieldInstance
 */
export function createNextShield(
  optionsOrInstance?: NextShieldOptions | ZShieldConfig | ZShieldInstance,
  adapterOptions?: NextShieldOptions
): NextShieldInstance {
  let config: ZShieldConfig;
  let rateLimiter: RateLimiter;
  let detector: Detector;
  let blockManager: BlockManager;
  let logger: Logger;
  let customGetIp: NextClientIpExtractor | NextClientIpStrategy | undefined;
  let customBlockResponse:
    | ((info: { reason: string; retryAfter: number; clientIp: string }) => Response)
    | undefined;

  if (isZShieldInstance(optionsOrInstance)) {
    config = optionsOrInstance.config;
    rateLimiter = optionsOrInstance.rateLimiter;
    detector = optionsOrInstance.detector;
    blockManager = optionsOrInstance.blockManager;
    logger = optionsOrInstance.logger;
    if (adapterOptions?.getIp) {
      customGetIp = adapterOptions.getIp;
    }
    if (adapterOptions?.customBlockResponse) {
      customBlockResponse = adapterOptions.customBlockResponse;
    }
  } else {
    const opts = optionsOrInstance || {};
    config = resolveConfig(opts);
    rateLimiter = new RateLimiter(config);
    detector = new Detector({ rateLimiter, config });
    blockManager = new BlockManager(config);
    logger = new Logger(config);
    if ('getIp' in opts && (typeof opts.getIp === 'function' || typeof opts.getIp === 'string')) {
      customGetIp = opts.getIp;
    }
    if ('customBlockResponse' in opts && typeof opts.customBlockResponse === 'function') {
      customBlockResponse = opts.customBlockResponse;
    }
  }

  const check = async (
    request: Request | NextLikeRequest
  ): Promise<NextShieldCheckResult> => {
    const pathname = extractRequestPath(request);
    const method = (request.method || 'GET').toUpperCase();
    const now = Date.now();

    // 1. Route exclusion check
    if (isRouteExcluded(pathname, config.excludeRoutes)) {
      return {
        blocked: false,
        isExcluded: true,
        clientIp: '',
        headers: {}
      };
    }

    // 2. Client IP extraction
    const clientIp = extractNextClientIp(request, config.trustProxy, customGetIp);

    // 3. BlockManager check
    const isIpBlocked = blockManager.isBlocked(clientIp, now);
    if (isIpBlocked) {
      const blockInfo = blockManager.getBlockInfo(clientIp, now);
      const reason = blockInfo ? blockInfo.reason : 'Administrative block';
      const remainingMs = blockInfo ? blockInfo.remainingMs : 0;
      const retryAfterSeconds = Math.max(1, Math.ceil(remainingMs / 1000));
      const action = config.mode === 'protect' ? 'blocked' : 'warned';

      void logger.log({
        appName: config.appName,
        type: 'blocked_ip',
        severity: 'warning',
        ip: clientIp,
        method,
        route: pathname,
        reason,
        action
      });

      const headers: Record<string, string> = {
        'X-Z-Shield-Protected': '1',
        'X-Z-Shield-Mode': config.mode,
        'X-Z-Shield-Blocked': '1',
        'X-Z-Shield-Reason': reason,
        'Retry-After': String(retryAfterSeconds)
      };

      if (config.mode === 'protect') {
        const blockedResponse = createBlockedResponse(
          retryAfterSeconds,
          'Your IP address has been temporarily blocked due to suspicious activity.',
          headers,
          customBlockResponse,
          clientIp
        );
        return {
          blocked: true,
          isExcluded: false,
          clientIp,
          headers,
          response: blockedResponse
        };
      }

      // Monitor mode: mark warning header and allow request through
      headers['X-Z-Shield-Suspicious'] = '1';
      return {
        blocked: false,
        isExcluded: false,
        clientIp,
        headers
      };
    }

    // 4. Rate Limiting assessment via Detector
    const detection = detector.check(clientIp, request, now);
    const rateLimitHeaders: Record<string, string> = {
      'X-Z-Shield-Protected': '1',
      'X-Z-Shield-Mode': config.mode,
      'X-RateLimit-Limit': String(config.maxRequests),
      'X-RateLimit-Remaining': String(detection.remaining),
      'X-RateLimit-Reset': String(Math.ceil(detection.resetTime / 1000))
    };

    if (detection.isSuspicious) {
      const action = config.mode === 'protect' ? 'blocked' : 'warned';
      void logger.log({
        appName: config.appName,
        type: detection.type || 'rate_limit',
        severity: detection.severity || 'warning',
        ip: clientIp,
        method,
        route: pathname,
        reason: detection.reason || 'Threshold exceeded',
        action
      });

      rateLimitHeaders['X-Z-Shield-Suspicious'] = '1';
      rateLimitHeaders['X-Z-Shield-Reason'] = detection.reason || 'Threshold exceeded';

      if (config.mode === 'protect') {
        if (config.autoBlock && isValidIp(clientIp)) {
          blockManager.block(clientIp, config.blockDurationMs, detection.reason || 'Threshold exceeded', now);
        }

        const retryAfterSeconds = Math.max(1, Math.ceil((detection.resetTime - now) / 1000));
        rateLimitHeaders['Retry-After'] = String(retryAfterSeconds);
        rateLimitHeaders['X-Z-Shield-Blocked'] = '1';

        const blockedResponse = createBlockedResponse(
          retryAfterSeconds,
          'Rate limit exceeded. Please wait before retrying.',
          rateLimitHeaders,
          customBlockResponse,
          clientIp
        );

        return {
          blocked: true,
          isExcluded: false,
          clientIp,
          detection,
          headers: rateLimitHeaders,
          response: blockedResponse
        };
      }
    }

    // 5. Allowed / normal request
    return {
      blocked: false,
      isExcluded: false,
      clientIp,
      detection,
      headers: rateLimitHeaders
    };
  };

  const protect = <TContext = unknown>(
    handler: (request: Request, context?: TContext) => Promise<Response> | Response
  ): ((request: Request, context?: TContext) => Promise<Response>) => {
    return async (request: Request, context?: TContext): Promise<Response> => {
      const checkResult = await check(request);

      if (checkResult.blocked && checkResult.response) {
        return checkResult.response;
      }

      const response = await handler(request, context);

      if (checkResult.isExcluded || Object.keys(checkResult.headers).length === 0) {
        return response;
      }

      return mergeResponseHeaders(response, checkResult.headers);
    };
  };

  return {
    config,
    rateLimiter,
    detector,
    blockManager,
    logger,
    check,
    protect,

    // Programmatic Block API
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

/**
 * Higher-order function wrapping a Next.js App Router route handler with Z-Shield protection.
 *
 * Usage:
 *   import { withNextShield } from 'z-shield';
 *
 *   export const GET = withNextShield(async (req) => {
 *     return Response.json({ ok: true });
 *   }, { mode: 'protect', maxRequests: 50 });
 *
 * @param handler - Next.js Route Handler function
 * @param options - Z-Shield configuration options or existing shield instance
 * @returns Wrapped route handler
 */
export function withNextShield<TContext = unknown>(
  handler: (request: Request, context?: TContext) => Promise<Response> | Response,
  options?: NextShieldOptions | ZShieldConfig | NextShieldInstance | ZShieldInstance,
  adapterOptions?: NextShieldOptions
): (request: Request, context?: TContext) => Promise<Response> {
  const shield =
    options && 'protect' in options
      ? (options as NextShieldInstance)
      : createNextShield(
          options as NextShieldOptions | ZShieldConfig | ZShieldInstance | undefined,
          adapterOptions
        );

  return shield.protect(handler);
}
