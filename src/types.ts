/**
 * Z-Shield Core Type Definitions
 */

import type { RateLimiter } from './rate-limiter';
import type { Detector } from './detector';
import type { BlockManager, BlockInfo } from './block-manager';
import type { Logger } from './logger';

export type ZShieldMode = 'monitor' | 'protect';

export interface ZShieldOptions {
  mode?: ZShieldMode;
  windowMs?: number;
  maxRequests?: number;
  maxTrackedIps?: number;
  autoBlock?: boolean;
  blockDurationMs?: number;
  blockDuration?: string | number;
  maxBlockedIps?: number;
  trustProxy?: boolean;
  logDir?: string;
  logFilename?: string;
  appName?: string;
  excludeRoutes?: string[] | readonly string[];
  maxLogSizeBytes?: number;
  maxLogFiles?: number;
  maxLogQueueSize?: number;
  onLogError?: ((err: Error, event: Record<string, unknown>) => void) | null;
}

export interface ZShieldConfig {
  readonly mode: ZShieldMode;
  readonly windowMs: number;
  readonly maxRequests: number;
  readonly maxTrackedIps: number;
  readonly autoBlock: boolean;
  readonly blockDurationMs: number;
  readonly blockDuration?: string | number;
  readonly maxBlockedIps: number;
  readonly trustProxy: boolean;
  readonly logDir: string;
  readonly logFilename: string;
  readonly appName: string;
  readonly excludeRoutes: readonly string[];
  readonly maxLogSizeBytes: number;
  readonly maxLogFiles: number;
  readonly maxLogQueueSize: number;
  readonly onLogError: ((err: Error, event: Record<string, unknown>) => void) | null;
}

export interface RateLimitStatus {
  count: number;
  remaining: number;
  resetTime: number;
  isExceeded: boolean;
}

export interface BlockRecord {
  ip: string;
  blockedAt: number;
  expiresAt: number;
  reason: string;
  durationMs: number;
}

export type { BlockInfo } from './block-manager';

export type SecurityEventType =
  | 'rate_limit'
  | 'manual_block'
  | 'manual_unblock'
  | 'suspicious_activity'
  | string;

export type SecurityEventAction =
  | 'blocked'
  | 'warning'
  | 'audit'
  | 'unblocked'
  | string;

export interface SecurityEvent {
  timestamp: string;
  appName: string;
  ip: string;
  type: SecurityEventType;
  action: SecurityEventAction;
  route?: string;
  method?: string;
  reason?: string;
  details?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface DetectionResult {
  status: 'normal' | 'suspicious' | 'blocked';
  reason?: string;
  rateLimitStatus: RateLimitStatus;
  isBlocked: boolean;
}

/**
 * Structural types for Express-compatible HTTP requests and responses.
 * These types do not require installing @types/express in consumer projects.
 */
export interface ExpressLikeRequest {
  ip?: string;
  url?: string;
  path?: string;
  method?: string;
  socket?: { remoteAddress?: string };
  headers?: Record<string, string | string[] | undefined>;
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

export interface ExpressLikeResponse {
  headersSent?: boolean;
  writableEnded?: boolean;
  setHeader?(name: string, value: string): void;
  status?(code: number): this | ExpressLikeResponse;
  json?(body: unknown): void;
  end?(): void;
}

export type ExpressLikeNextFunction = (err?: unknown) => void;

export type ExpressMiddleware<
  Req = ExpressLikeRequest,
  Res = ExpressLikeResponse,
  Next = ExpressLikeNextFunction
> = (req: Req, res: Res, next: Next) => void;

export interface ZShieldInstance {
  readonly middleware: ExpressMiddleware;
  readonly config: ZShieldConfig;
  readonly rateLimiter: RateLimiter;
  readonly detector: Detector;
  readonly blockManager: BlockManager;
  readonly logger: Logger;
  block: (ip: string, duration?: string | number, reason?: string) => BlockRecord;
  unblock: (ip: string) => boolean;
  isBlocked: (ip: string) => boolean;
  getBlockInfo: (ip: string) => BlockInfo | null;
  listBlocks: () => BlockInfo[];
  flush: () => Promise<void>;
}

export type ZShieldFullInstance = ZShieldInstance;

/**
 * Structural type for Web-standard or Next.js requests.
 */
export interface NextLikeRequest {
  url?: string;
  method?: string;
  headers?: Headers | Record<string, string | string[] | undefined> | { get(name: string): string | null };
  ip?: string;
  socket?: { remoteAddress?: string };
}

export type NextClientIpStrategy =
  | 'x-forwarded-for'
  | 'x-real-ip'
  | 'nginx'
  | 'cf-connecting-ip'
  | 'cloudflare'
  | 'true-client-ip'
  | 'akamai';

export type NextClientIpExtractor = (
  request: Request | NextLikeRequest
) => string | null | undefined;

export interface NextShieldOptions extends ZShieldOptions {
  /**
   * Explicit client IP extraction strategy or custom callback function.
   *
   * To safely extract client IPs behind a reverse proxy, explicitly specify your
   * trusted deployment proxy strategy or provide a custom extraction callback:
   * - 'cloudflare' | 'cf-connecting-ip': Trusts only the CF-Connecting-IP header.
   * - 'nginx' | 'x-real-ip': Trusts only the X-Real-IP header.
   * - 'akamai' | 'true-client-ip': Trusts only the True-Client-IP header.
   * - 'x-forwarded-for': Trusts the first valid IP in X-Forwarded-For.
   * - Custom function: `(req) => string | null | undefined`
   */
  getIp?: NextClientIpStrategy | NextClientIpExtractor;

  /**
   * Optional custom 429 response builder.
   */
  customBlockResponse?: (info: { reason: string; retryAfter: number; clientIp: string }) => Response;
}

export interface NextShieldCheckResult {
  blocked: boolean;
  isExcluded: boolean;
  clientIp: string;
  headers: Record<string, string>;
  response?: Response;
  detection?: {
    isSuspicious: boolean;
    count: number;
    remaining: number;
    resetTime: number;
    reason: string | null;
  };
}

export type NextRouteHandler<TContext = unknown> = (
  request: Request,
  context?: TContext
) => Promise<Response> | Response;

export interface NextShieldInstance {
  readonly config: ZShieldConfig;
  readonly rateLimiter: RateLimiter;
  readonly detector: Detector;
  readonly blockManager: BlockManager;
  readonly logger: Logger;
  check: (request: Request | NextLikeRequest) => Promise<NextShieldCheckResult>;
  protect: <TContext = unknown>(
    handler: (request: Request, context?: TContext) => Promise<Response> | Response
  ) => (request: Request, context?: TContext) => Promise<Response>;
  block: (ip: string, duration?: string | number, reason?: string) => BlockRecord;
  unblock: (ip: string) => boolean;
  isBlocked: (ip: string) => boolean;
  getBlockInfo: (ip: string) => BlockInfo | null;
  listBlocks: () => BlockInfo[];
  flush: () => Promise<void>;
}
