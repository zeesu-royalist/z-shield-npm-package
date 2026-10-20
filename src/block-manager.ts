import net from 'node:net';
import type { BlockRecord, ZShieldConfig, ZShieldOptions } from './types';

export interface BlockManagerOptions {
  blockDurationMs?: number;
  maxBlockedIps?: number;
}

export interface BlockInfo {
  ip: string;
  blockedAt: number;
  expiresAt: number;
  remainingMs: number;
  reason: string;
}

interface InternalBlockEntry {
  blockedAt: number;
  expiresAt: number;
  reason: string;
}

/**
 * Canonicalizes an IPv6 address string according to RFC 5952.
 * - Parses 16-bit hextets
 * - Handles embedded IPv4 in IPv6 (including IPv4-mapped IPv6)
 * - Normalizes loopback ('::1' and '0:0:0:0:0:0:0:1') to '127.0.0.1'
 * - Normalizes IPv4-mapped addresses to standard IPv4
 * - Compresses the longest run of 2 or more zeros with '::' (first run on tie)
 * - Lowers all hexadecimal characters and removes leading zeros in each field
 *
 * @param ip - Valid IPv6 address string
 * @returns Canonicalized representation
 */
export function canonicalizeIpv6(ip: string): string {
  let str = ip.toLowerCase().trim();
  const zoneIndex = str.indexOf('%');
  if (zoneIndex !== -1) {
    str = str.substring(0, zoneIndex);
  }

  // Handle embedded IPv4 (e.g. ::ffff:192.0.2.1)
  let embeddedIpv4: number[] | null = null;
  const lastColon = str.lastIndexOf(':');
  if (lastColon !== -1) {
    const candidateIpv4 = str.substring(lastColon + 1);
    if (candidateIpv4.includes('.')) {
      if (net.isIP(candidateIpv4) === 4) {
        embeddedIpv4 = candidateIpv4.split('.').map(Number);
        str = str.substring(0, lastColon) + ':0:0';
      } else {
        return ip.toLowerCase().trim();
      }
    }
  }

  const parts = str.split('::');
  if (parts.length > 2) {
    return ip.toLowerCase().trim();
  }

  const head = parts[0] ? parts[0].split(':').filter(Boolean) : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':').filter(Boolean) : [];

  const totalHextets = head.length + tail.length;
  if (parts.length === 1 && totalHextets !== 8) {
    return ip.toLowerCase().trim();
  }
  if (parts.length === 2 && totalHextets >= 8) {
    return ip.toLowerCase().trim();
  }

  const missingZeros = 8 - totalHextets;
  const hextets: number[] = [];

  for (const h of head) {
    const val = parseInt(h, 16);
    if (isNaN(val) || val < 0 || val > 0xffff) {
      return ip.toLowerCase().trim();
    }
    hextets.push(val);
  }
  for (let i = 0; i < missingZeros; i++) {
    hextets.push(0);
  }
  for (const t of tail) {
    const val = parseInt(t, 16);
    if (isNaN(val) || val < 0 || val > 0xffff) {
      return ip.toLowerCase().trim();
    }
    hextets.push(val);
  }

  if (hextets.length !== 8) {
    return ip.toLowerCase().trim();
  }

  if (embeddedIpv4 && embeddedIpv4.length === 4) {
    hextets[6] = ((embeddedIpv4[0] ?? 0) << 8) | (embeddedIpv4[1] ?? 0);
    hextets[7] = ((embeddedIpv4[2] ?? 0) << 8) | (embeddedIpv4[3] ?? 0);
  }

  // IPv4-mapped IPv6: ::ffff:w.x.y.z or 0:0:0:0:0:ffff:w.x.y.z
  const isIpv4Mapped =
    hextets[0] === 0 &&
    hextets[1] === 0 &&
    hextets[2] === 0 &&
    hextets[3] === 0 &&
    hextets[4] === 0 &&
    hextets[5] === 0xffff;
  if (isIpv4Mapped) {
    const h6 = hextets[6] ?? 0;
    const h7 = hextets[7] ?? 0;
    const b0 = (h6 >> 8) & 0xff;
    const b1 = h6 & 0xff;
    const b2 = (h7 >> 8) & 0xff;
    const b3 = h7 & 0xff;
    return `${b0}.${b1}.${b2}.${b3}`;
  }

  // IPv6 Loopback: ::1 or 0:0:0:0:0:0:0:1 -> 127.0.0.1
  const isLoopback = hextets.slice(0, 7).every((h) => h === 0) && hextets[7] === 1;
  if (isLoopback) {
    return '127.0.0.1';
  }

  // Find longest contiguous run of zeros (length >= 2) under RFC 5952
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < 8; i++) {
    if (hextets[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen++;
      }
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  // If no zero sequence of 2 or more hextets exists, join all 8 hextets
  if (bestLen < 2) {
    return hextets.map((h) => h.toString(16)).join(':');
  }

  const headStr = hextets.slice(0, bestStart).map((h) => h.toString(16)).join(':');
  const tailStr = hextets.slice(bestStart + bestLen).map((h) => h.toString(16)).join(':');
  return `${headStr}::${tailStr}`;
}

/**
 * Normalizes an IP address for consistent comparison across IPv4 and IPv6.
 * - Trims whitespace
 * - Canonicalizes IPv6 addresses according to RFC 5952 (zero compression, lowercase)
 * - Unmaps all IPv4-mapped IPv6 variations (e.g. '::ffff:192.168.1.1' -> '192.168.1.1')
 * - Normalizes all IPv6 loopback variants ('::1', '0:0:0:0:0:0:0:1') to '127.0.0.1'
 * - Preserves invalid strings without converting them into fake valid IPs
 *
 * @param ip - Raw client IP candidate
 * @returns Normalized IP or 'unknown'
 */
export function normalizeIp(ip: unknown): string {
  if (typeof ip !== 'string') {
    return 'unknown';
  }
  const trimmed = ip.trim();
  if (trimmed.length === 0) {
    return 'unknown';
  }

  // Standard valid IPv4
  const ipType = net.isIP(trimmed);
  if (ipType === 4) {
    return trimmed;
  }

  // Standard valid IPv6 (including loopback and IPv4-mapped)
  if (ipType === 6) {
    return canonicalizeIpv6(trimmed);
  }

  // Handle possible ::ffff:192.0.2.1 where net.isIP might return 0
  const lower = trimmed.toLowerCase();
  if (lower.startsWith('::ffff:')) {
    const candidateIpv4 = trimmed.substring(7);
    if (net.isIP(candidateIpv4) === 4) {
      return candidateIpv4;
    }
  }

  return trimmed;
}

/**
 * Validates whether an IP address is a valid IPv4 or IPv6 string.
 * Uses Node.js built-in net.isIP (returns 4 for IPv4, 6 for IPv6, 0 for invalid).
 *
 * @param ip - IP candidate string
 * @returns True if valid IPv4 or IPv6
 */
export function isValidIp(ip: unknown): boolean {
  if (typeof ip !== 'string' || ip.trim().length === 0) {
    return false;
  }
  const norm = normalizeIp(ip);
  return net.isIP(norm) !== 0;
}

/**
 * Parses block duration into milliseconds.
 * Supports numbers (milliseconds) or human-readable strings ('30s', '10m', '1h', '2d').
 *
 * @param duration - Numeric ms or formatted string
 * @returns Duration in milliseconds
 */
export function parseDuration(duration: number | string): number {
  if (typeof duration === 'number') {
    const ms = Math.floor(duration);
    if (!Number.isFinite(duration) || duration <= 0 || ms <= 0) {
      throw new TypeError('[Z-Shield] Block duration must be a positive number in milliseconds.');
    }
    return ms;
  }

  if (typeof duration === 'string') {
    const trimmed = duration.trim();
    const match = trimmed.match(/^(-?\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$/i);
    if (!match) {
      throw new Error(`[Z-Shield] Invalid duration format: "${duration}". Use format like "10m", "1h", "30s", or milliseconds.`);
    }
    const rawVal = match[1];
    if (rawVal === undefined) {
      throw new Error('[Z-Shield] Block duration must be greater than zero.');
    }
    const val = parseFloat(rawVal);
    if (!Number.isFinite(val) || val <= 0) {
      throw new Error('[Z-Shield] Block duration must be greater than zero.');
    }
    const unit = (match[2] || 'ms').toLowerCase();
    let ms: number;
    switch (unit) {
      case 'ms': ms = Math.floor(val); break;
      case 's': ms = Math.floor(val * 1000); break;
      case 'm': ms = Math.floor(val * 60 * 1000); break;
      case 'h': ms = Math.floor(val * 60 * 60 * 1000); break;
      case 'd': ms = Math.floor(val * 24 * 60 * 60 * 1000); break;
      default: ms = Math.floor(val); break;
    }
    if (ms <= 0) {
      throw new Error('[Z-Shield] Block duration must be greater than zero.');
    }
    return ms;
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
export class BlockManager {
  readonly defaultDurationMs: number;
  readonly maxBlockedIps: number;
  private readonly blocks: Map<string, InternalBlockEntry>;

  /**
   * @param options - Block manager options or resolved config
   */
  constructor(options: BlockManagerOptions | ZShieldConfig | ZShieldOptions = {}) {
    this.defaultDurationMs = options.blockDurationMs || 15 * 60 * 1000;
    this.maxBlockedIps = options.maxBlockedIps || 5000;

    this.blocks = new Map<string, InternalBlockEntry>();
  }

  /**
   * Temporarily blocks an IP address.
   *
   * @param ip - Valid IPv4 or IPv6 address
   * @param duration - Duration in ms or string ('10m')
   * @param reason - Reason for block
   * @param now - Current timestamp (injectable for testing)
   * @returns Created block record
   */
  block(
    ip: string,
    duration: number | string = this.defaultDurationMs,
    reason: string = 'Administrative block',
    now: number = Date.now()
  ): BlockRecord {
    if (!isValidIp(ip)) {
      throw new TypeError(`[Z-Shield] Cannot block invalid IP address: "${ip}".`);
    }

    const durationMs = parseDuration(duration);
    const cleanIp = normalizeIp(ip);

    // Bound memory: if at capacity, evict an old entry before inserting
    if (this.blocks.size >= this.maxBlockedIps && !this.blocks.has(cleanIp)) {
      this._evictOldest(now);
    }

    const entry: InternalBlockEntry = {
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
   * @param ip - Client IP
   * @returns True if IP was unblocked, false if it was not blocked
   */
  unblock(ip: string): boolean {
    if (!isValidIp(ip)) {
      throw new TypeError(`[Z-Shield] Cannot unblock invalid IP address: "${ip}".`);
    }
    return this.blocks.delete(normalizeIp(ip));
  }

  /**
   * Checks whether an IP address is currently blocked.
   * Expired blocks are lazily pruned.
   *
   * @param ip - Client IP
   * @param now - Current timestamp
   * @returns True if actively blocked
   */
  isBlocked(ip: string | undefined | null, now: number = Date.now()): boolean {
    if (!ip || typeof ip !== 'string') {
      return false;
    }

    const cleanIp = normalizeIp(ip);
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
   * @param ip - Client IP
   * @param now - Current timestamp
   * @returns Block information or null
   */
  getBlockInfo(ip: string, now: number = Date.now()): BlockInfo | null {
    if (!this.isBlocked(ip, now)) {
      return null;
    }

    const cleanIp = normalizeIp(ip);
    const entry = this.blocks.get(cleanIp);
    if (!entry) {
      return null;
    }

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
   * @param now - Current timestamp
   * @returns Array of active block records
   */
  listBlocks(now: number = Date.now()): BlockInfo[] {
    this.pruneExpired(now);
    const result: BlockInfo[] = [];
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
   * @param now - Current timestamp
   * @returns Number of purged blocks
   */
  pruneExpired(now: number = Date.now()): number {
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
  clear(): void {
    this.blocks.clear();
  }

  /**
   * Number of IPs currently stored in memory.
   */
  get size(): number {
    return this.blocks.size;
  }

  /**
   * Evicts the oldest entry to strictly uphold maxBlockedIps limit.
   *
   * @param _now - Current timestamp
   */
  private _evictOldest(_now: number): void {
    const iterator = this.blocks.keys();
    const firstKey = iterator.next().value;

    if (firstKey !== undefined) {
      this.blocks.delete(firstKey);
    }
  }
}
