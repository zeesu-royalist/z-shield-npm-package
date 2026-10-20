import type { RateLimiter } from './rate-limiter';
import type { ZShieldConfig } from './types';

export interface DetectorOptions {
  rateLimiter: RateLimiter;
  config: ZShieldConfig;
}

export interface CheckResult {
  isSuspicious: boolean;
  type: string;
  severity: string;
  reason: string | null;
  count: number;
  maxRequests: number;
  remaining: number;
  resetTime: number;
  timestamp: string;
}

export interface InspectResult {
  isSuspicious: boolean;
  count: number;
  maxRequests: number;
  remaining: number;
  resetTime: number;
}

/**
 * Detector - Evaluates incoming requests and detects abuse patterns.
 *
 * In Phase 2, this evaluates whether a client IP has exceeded the
 * maximum request threshold within the configured time window.
 */
export class Detector {
  readonly rateLimiter: RateLimiter;
  readonly config: ZShieldConfig;

  /**
   * @param options - Configuration containing rateLimiter and resolved config
   */
  constructor({ rateLimiter, config }: DetectorOptions) {
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
   * @param ip - Client IP address
   * @param req - Request object (Express Request or standard Request)
   * @param now - Timestamp
   * @returns Detection evaluation result
   */
  check(ip: string, req: unknown = {}, now: number = Date.now()): CheckResult {
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
   * @param ip - Client IP address
   * @param now - Timestamp
   * @returns Inspection status
   */
  inspect(ip: string, now: number = Date.now()): InspectResult {
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
