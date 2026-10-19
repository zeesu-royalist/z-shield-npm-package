'use strict';

const net = require('node:net');

/**
 * Validates whether an IP address is a valid IPv4 or IPv6 string.
 * Uses Node.js built-in net.isIP (returns 4 for IPv4, 6 for IPv6, 0 for invalid).
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isValidIp(ip) {
  if (typeof ip !== 'string' || ip.trim().length === 0) {
    return false;
  }
  return net.isIP(ip.trim()) !== 0;
}

/**
 * Parses block duration into milliseconds.
 * Supports numbers (milliseconds) or human-readable strings ('30s', '10m', '1h', '2d').
 *
 * @param {number|string} duration
 * @returns {number} duration in milliseconds
 */
function parseDuration(duration) {
  if (typeof duration === 'number') {
    if (!Number.isFinite(duration) || duration <= 0) {
      throw new TypeError('[Z-Shield] Block duration must be a positive number in milliseconds.');
    }
    return Math.floor(duration);
  }

  if (typeof duration === 'string') {
    const match = duration.trim().match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$/i);
    if (!match) {
      throw new Error(`[Z-Shield] Invalid duration format: "${duration}". Use format like "10m", "1h", "30s", or milliseconds.`);
    }
    const val = parseFloat(match[1]);
    const unit = (match[2] || 'ms').toLowerCase();
    switch (unit) {
      case 'ms': return Math.floor(val);
      case 's': return Math.floor(val * 1000);
      case 'm': return Math.floor(val * 60 * 1000);
      case 'h': return Math.floor(val * 60 * 60 * 1000);
      case 'd': return Math.floor(val * 24 * 60 * 60 * 1000);
      default: return Math.floor(val);
    }
  }

  throw new TypeError('[Z-Shield] Block duration must be a number (milliseconds) or a duration string like "10m".');
}

/**
 * BlockManager - In-Memory Temporary IP Block Management
 *
 * Characteristics:
 * - Process-Local: Blocks are held in RAM. They do NOT survive server restarts.
 * - Automatic Expiry: Block entries are checked against their expiration timestamp.
 * - Bounded Memory: Uses LRU eviction when `maxBlockedIps` is reached to prevent memory exhaustion.
 * - No Background Timers: Uses passive/lazy expiration on access to keep Node.js event loop idle.
 */
class BlockManager {
  /**
   * @param {Object} [options={}]
   * @param {number} [options.blockDurationMs=900000] - Default block duration in ms (15 min)
   * @param {number} [options.maxBlockedIps=5000] - Max blocked IPs in memory
   */
  constructor(options = {}) {
    this.defaultDurationMs = options.blockDurationMs || 15 * 60 * 1000;
    this.maxBlockedIps = options.maxBlockedIps || 5000;

    /** @type {Map<string, { blockedAt: number, expiresAt: number, reason: string }>} */
    this.blocks = new Map();
  }

  /**
   * Temporarily blocks an IP address.
   *
   * @param {string} ip - Valid IPv4 or IPv6 address
   * @param {number|string} [duration=this.defaultDurationMs] - Duration in ms or string ('10m')
   * @param {string} [reason='Administrative block'] - Reason for block
   * @param {number} [now=Date.now()] - Current timestamp (injectable for testing)
   * @returns {{ ip: string, blockedAt: number, expiresAt: number, durationMs: number, reason: string }}
   */
  block(ip, duration = this.defaultDurationMs, reason = 'Administrative block', now = Date.now()) {
    if (!isValidIp(ip)) {
      throw new TypeError(`[Z-Shield] Cannot block invalid IP address: "${ip}".`);
    }

    const durationMs = parseDuration(duration);
    const cleanIp = ip.trim();

    // Bound memory: if at capacity, evict an old entry before inserting
    if (this.blocks.size >= this.maxBlockedIps && !this.blocks.has(cleanIp)) {
      this._evictOldest(now);
    }

    const entry = {
      blockedAt: now,
      expiresAt: now + durationMs,
      reason: String(reason || 'Administrative block')
    };

    // Refresh LRU order: delete if exists, then set
    this.blocks.delete(cleanIp);
    this.blocks.set(cleanIp, entry);

    return {
      ip: cleanIp,
      blockedAt: entry.blockedAt,
      expiresAt: entry.expiresAt,
      durationMs,
      reason: entry.reason
    };
  }

  /**
   * Manually unblocks an IP address.
   *
   * @param {string} ip - Client IP
   * @returns {boolean} True if IP was unblocked, false if it was not blocked
   */
  unblock(ip) {
    if (!isValidIp(ip)) {
      throw new TypeError(`[Z-Shield] Cannot unblock invalid IP address: "${ip}".`);
    }
    return this.blocks.delete(ip.trim());
  }

  /**
   * Checks whether an IP address is currently blocked.
   * Expired blocks are lazily pruned.
   *
   * @param {string} ip
   * @param {number} [now=Date.now()]
   * @returns {boolean}
   */
  isBlocked(ip, now = Date.now()) {
    if (!ip || typeof ip !== 'string') {
      return false;
    }

    const cleanIp = ip.trim();
    const entry = this.blocks.get(cleanIp);

    if (!entry) {
      return false;
    }

    // Lazy expiration check
    if (now >= entry.expiresAt) {
      this.blocks.delete(cleanIp);
      return false;
    }

    return true;
  }

  /**
   * Retrieves active block details for an IP, or null if not blocked/expired.
   *
   * @param {string} ip
   * @param {number} [now=Date.now()]
   * @returns {{ ip: string, blockedAt: number, expiresAt: number, remainingMs: number, reason: string } | null}
   */
  getBlockInfo(ip, now = Date.now()) {
    if (!this.isBlocked(ip, now)) {
      return null;
    }

    const cleanIp = ip.trim();
    const entry = this.blocks.get(cleanIp);

    return {
      ip: cleanIp,
      blockedAt: entry.blockedAt,
      expiresAt: entry.expiresAt,
      remainingMs: Math.max(0, entry.expiresAt - now),
      reason: entry.reason
    };
  }

  /**
   * Returns a list of all currently active blocked IPs.
   *
   * @param {number} [now=Date.now()]
   * @returns {Array<{ ip: string, blockedAt: number, expiresAt: number, remainingMs: number, reason: string }>}
   */
  listBlocks(now = Date.now()) {
    this.pruneExpired(now);
    const result = [];
    for (const [ip, entry] of this.blocks.entries()) {
      result.push({
        ip,
        blockedAt: entry.blockedAt,
        expiresAt: entry.expiresAt,
        remainingMs: Math.max(0, entry.expiresAt - now),
        reason: entry.reason
      });
    }
    return result;
  }

  /**
   * Scans and purges any expired blocks from memory.
   *
   * @param {number} [now=Date.now()]
   * @returns {number} Number of purged blocks
   */
  pruneExpired(now = Date.now()) {
    let pruned = 0;
    for (const [ip, entry] of this.blocks.entries()) {
      if (now >= entry.expiresAt) {
        this.blocks.delete(ip);
        pruned++;
      }
    }
    return pruned;
  }

  /**
   * Clears all blocks from memory.
   */
  clear() {
    this.blocks.clear();
  }

  /**
   * Number of IPs currently stored in memory.
   * @returns {number}
   */
  get size() {
    return this.blocks.size;
  }

  /**
   * Evicts the oldest entry to strictly uphold maxBlockedIps limit.
   * @private
   * @param {number} now
   */
  _evictOldest(now) {
    const iterator = this.blocks.entries();
    const first = iterator.next().value;

    if (!first) {
      return;
    }

    const [oldestIp, oldestEntry] = first;

    // If oldest is already expired, delete it
    if (now >= oldestEntry.expiresAt) {
      this.blocks.delete(oldestIp);
      return;
    }

    // Evict oldest LRU entry
    this.blocks.delete(oldestIp);
  }
}

module.exports = {
  BlockManager,
  isValidIp,
  parseDuration
};
