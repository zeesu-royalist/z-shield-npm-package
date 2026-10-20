import { normalizeIp } from './block-manager';
import type { RateLimitStatus, ZShieldConfig, ZShieldOptions } from './types';

export interface RateLimiterOptions {
  windowMs?: number;
  maxRequests?: number;
  maxTrackedIps?: number;
}

interface CounterEntry {
  count: number;
  resetTime: number;
}

/**
 * RateLimiter - Bounded In-Memory Request Counter
 *
 * Algorithm: Fixed Window with Per-IP Dynamic Reset Time
 * - On an IP's first request, we establish a time window (now -> now + windowMs).
 * - Every subsequent request within the window increments the counter.
 * - When the window expires, the counter resets to 1 with a new window.
 *
 * Memory Protection (DoS defense):
 * - JavaScript's Map preserves insertion order.
 * - By deleting and re-setting accessed keys, the Map functions as an LRU (Least Recently Used) cache.
 * - If the number of tracked IPs reaches `maxTrackedIps`, we evict the oldest entry.
 *   This ensures memory consumption is strictly bounded and cannot crash the Node.js process.
 */
export class RateLimiter {
  readonly windowMs: number;
  readonly maxRequests: number;
  readonly maxTrackedIps: number;
  private readonly records: Map<string, CounterEntry>;

  /**
   * @param options - Limiter options or resolved configuration
   */
  constructor(options: RateLimiterOptions | ZShieldConfig | ZShieldOptions = {}) {
    this.windowMs = options.windowMs || 60000;
    this.maxRequests = options.maxRequests || 100;
    this.maxTrackedIps = options.maxTrackedIps || 10000;

    this.records = new Map<string, CounterEntry>();
  }

  /**
   * Records an incoming request from an IP address.
   *
   * @param ip - Client IP address
   * @param now - Current timestamp (injectable for testing)
   * @returns Current rate limit status
   */
  record(ip: string, now: number = Date.now()): RateLimitStatus {
    const cleanIp = normalizeIp(ip);

    let entry = this.records.get(cleanIp);

    // If an existing entry has expired, treat it as a fresh window
    if (entry && now >= entry.resetTime) {
      entry = undefined;
    }

    if (entry) {
      // Existing active window: increment count
      entry.count += 1;

      // Refresh LRU order: delete and re-set so this IP is marked as most recently used
      this.records.delete(cleanIp);
      this.records.set(cleanIp, entry);
    } else {
      // New window or expired window: only evict if adding a NEW IP at capacity
      if (!this.records.has(cleanIp) && this.records.size >= this.maxTrackedIps) {
        this._evictOldest(now);
      }

      entry = {
        count: 1,
        resetTime: now + this.windowMs
      };

      // Delete first to ensure refreshed LRU order in Map
      this.records.delete(cleanIp);
      this.records.set(cleanIp, entry);
    }

    const remaining = Math.max(0, this.maxRequests - entry.count);
    const isExceeded = entry.count > this.maxRequests;

    return {
      count: entry.count,
      remaining,
      resetTime: entry.resetTime,
      isExceeded
    };
  }

  /**
   * Inspects current status for an IP without incrementing its counter.
   *
   * @param ip - Client IP address
   * @param now - Current timestamp
   * @returns Current rate limit status
   */
  get(ip: string, now: number = Date.now()): RateLimitStatus {
    const cleanIp = normalizeIp(ip);
    const entry = this.records.get(cleanIp);

    if (!entry || now >= entry.resetTime) {
      return {
        count: 0,
        remaining: this.maxRequests,
        resetTime: now + this.windowMs,
        isExceeded: false
      };
    }

    return {
      count: entry.count,
      remaining: Math.max(0, this.maxRequests - entry.count),
      resetTime: entry.resetTime,
      isExceeded: entry.count > this.maxRequests
    };
  }

  /**
   * Resets counter for a specific IP.
   * @param ip - Client IP address
   */
  reset(ip: string): void {
    const cleanIp = normalizeIp(ip);
    this.records.delete(cleanIp);
  }

  /**
   * Clears all tracked IP records from memory.
   */
  clear(): void {
    this.records.clear();
  }

  /**
   * Number of IPs currently stored in memory.
   */
  get size(): number {
    return this.records.size;
  }

  /**
   * Scans and removes any expired counters from memory.
   * Because Map maintains insertion order, oldest entries are checked first.
   *
   * @param now - Current timestamp
   * @returns Count of removed expired entries
   */
  pruneExpired(now: number = Date.now()): number {
    let pruned = 0;
    for (const [ip, entry] of this.records.entries()) {
      if (now >= entry.resetTime) {
        this.records.delete(ip);
        pruned++;
      }
    }
    return pruned;
  }

  /**
   * Evicts the oldest entry to maintain bounded memory.
   * Evicts the least recently used entry to strictly uphold memory bound.
   *
   * @param _now - Current timestamp
   */
  private _evictOldest(_now: number): void {
    const iterator = this.records.keys();
    const firstKey = iterator.next().value;

    if (firstKey !== undefined) {
      this.records.delete(firstKey);
    }
  }
}
