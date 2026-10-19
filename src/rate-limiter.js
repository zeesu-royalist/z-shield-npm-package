'use strict';

const { normalizeIp } = require('./block-manager');

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
class RateLimiter {
  /**
   * @param {Object} options
   * @param {number} [options.windowMs=60000] - Window length in milliseconds
   * @param {number} [options.maxRequests=100] - Max allowed requests per window
   * @param {number} [options.maxTrackedIps=10000] - Maximum unique IPs tracked in memory
   */
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60000;
    this.maxRequests = options.maxRequests || 100;
    this.maxTrackedIps = options.maxTrackedIps || 10000;

    /** @type {Map<string, { count: number, resetTime: number }>} */
    this.records = new Map();
  }

  /**
   * Records an incoming request from an IP address.
   *
   * @param {string} ip - Client IP address
   * @param {number} [now=Date.now()] - Current timestamp (injectable for testing)
   * @returns {{ count: number, remaining: number, resetTime: number, isExceeded: boolean }}
   */
  record(ip, now = Date.now()) {
    const cleanIp = normalizeIp(ip);

    let entry = this.records.get(cleanIp);

    // If an existing entry has expired, treat it as a fresh window
    if (entry && now >= entry.resetTime) {
      entry = null;
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
   * @param {string} ip
   * @param {number} [now=Date.now()]
   * @returns {{ count: number, remaining: number, resetTime: number, isExceeded: boolean }}
   */
  get(ip, now = Date.now()) {
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
   * @param {string} ip
   */
  reset(ip) {
    const cleanIp = normalizeIp(ip);
    this.records.delete(cleanIp);
  }

  /**
   * Clears all tracked IP records from memory.
   */
  clear() {
    this.records.clear();
  }

  /**
   * Number of IPs currently stored in memory.
   * @returns {number}
   */
  get size() {
    return this.records.size;
  }

  /**
   * Scans and removes any expired counters from memory.
   * Because Map maintains insertion order, oldest entries are checked first.
   *
   * @param {number} [now=Date.now()]
   * @returns {number} Count of removed expired entries
   */
  pruneExpired(now = Date.now()) {
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
   * Prefers to evict an expired entry first; if none are expired, evicts the LRU entry.
   *
   * @private
   * @param {number} now
   */
  _evictOldest(now) {
    const iterator = this.records.entries();
    const first = iterator.next().value;

    if (!first) {
      return;
    }

    const [oldestIp, oldestEntry] = first;

    // If oldest is already expired, delete it
    if (now >= oldestEntry.resetTime) {
      this.records.delete(oldestIp);
      return;
    }

    // Otherwise evict least recently used entry to strictly uphold memory bound
    this.records.delete(oldestIp);
  }
}

module.exports = {
  RateLimiter
};
