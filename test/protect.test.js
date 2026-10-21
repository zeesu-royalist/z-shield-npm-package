'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { BlockManager, isValidIp, normalizeIp, canonicalizeIpv6, maskIpv6Subnet, parseDuration } = require('../dist/block-manager');
const { RateLimiter } = require('../dist/rate-limiter');
const { createShield, resolveConfig } = require('../dist/index');
const { createNextShield } = require('../dist/next');

describe('Z-Shield Phase 3: Protection Mode & Temporary IP Blocking', () => {

  describe('BlockManager Unit Tests', () => {
    test('validates IPv4 and IPv6 addresses correctly', () => {
      assert.equal(isValidIp('192.168.1.1'), true);
      assert.equal(isValidIp('10.0.0.1'), true);
      assert.equal(isValidIp('127.0.0.1'), true);
      assert.equal(isValidIp('::1'), true);
      assert.equal(isValidIp('2001:db8::1'), true);

      assert.equal(isValidIp(''), false);
      assert.equal(isValidIp('not-an-ip'), false);
      assert.equal(isValidIp('999.999.999.999'), false);
      assert.equal(isValidIp(null), false);
      assert.equal(isValidIp(undefined), false);
    });

    test('parses block duration correctly in milliseconds or strings', () => {
      assert.equal(parseDuration(5000), 5000);
      assert.equal(parseDuration('500ms'), 500);
      assert.equal(parseDuration('30s'), 30000);
      assert.equal(parseDuration('10m'), 600000);
      assert.equal(parseDuration('1h'), 3600000);
      assert.equal(parseDuration('2d'), 172800000);
      assert.equal(parseDuration('1.5s'), 1500);
      assert.equal(parseDuration(' 10m '), 600000);

      assert.throws(() => parseDuration(-100), /Block duration must be a positive number/);
      assert.throws(() => parseDuration(0), /Block duration must be a positive number/);
      assert.throws(() => parseDuration('forever'), /Invalid duration format/);
      assert.throws(() => parseDuration({}), /Block duration must be a number/);
    });

    test('rejects zero and negative duration inputs consistently (P3 regression)', () => {
      // String inputs with units
      assert.throws(() => parseDuration('0s'), /Block duration must be greater than zero/);
      assert.throws(() => parseDuration('0m'), /Block duration must be greater than zero/);
      assert.throws(() => parseDuration('0ms'), /Block duration must be greater than zero/);
      assert.throws(() => parseDuration('0h'), /Block duration must be greater than zero/);
      assert.throws(() => parseDuration('0d'), /Block duration must be greater than zero/);
      assert.throws(() => parseDuration('0.0s'), /Block duration must be greater than zero/);
      assert.throws(() => parseDuration('0'), /Block duration must be greater than zero/);

      // Negative string inputs
      assert.throws(() => parseDuration('-5s'), /Block duration must be greater than zero/);
      assert.throws(() => parseDuration('-10m'), /Block duration must be greater than zero/);
      assert.throws(() => parseDuration('-100'), /Block duration must be greater than zero/);

      // Sub-millisecond rounding down to zero
      assert.throws(() => parseDuration('0.0001ms'), /Block duration must be greater than zero/);

      // Numeric inputs
      assert.throws(() => parseDuration(0), /Block duration must be a positive number/);
      assert.throws(() => parseDuration(-1), /Block duration must be a positive number/);
      assert.throws(() => parseDuration(-5000), /Block duration must be a positive number/);
      assert.throws(() => parseDuration(0.4), /Block duration must be a positive number/);

      // Verify BlockManager rejects zero durations
      const bm = new BlockManager();
      assert.throws(() => bm.block('198.51.100.1', '0s'), /Block duration must be greater than zero/);
      assert.throws(() => bm.block('198.51.100.1', '0m'), /Block duration must be greater than zero/);
      assert.throws(() => bm.block('198.51.100.1', '0ms'), /Block duration must be greater than zero/);
      assert.throws(() => bm.block('198.51.100.1', 0), /Block duration must be a positive number/);
      assert.equal(bm.isBlocked('198.51.100.1'), false);
    });

    test('blocks and unblocks an IP address', () => {
      const bm = new BlockManager({ maxBlockedIps: 100 });
      const now = 10000;

      assert.equal(bm.isBlocked('198.51.100.1', now), false);

      const blockEntry = bm.block('198.51.100.1', '10m', 'Suspicious activity', now);
      assert.equal(blockEntry.ip, '198.51.100.1');
      assert.equal(blockEntry.durationMs, 600000);
      assert.equal(blockEntry.expiresAt, now + 600000);
      assert.equal(blockEntry.reason, 'Suspicious activity');

      assert.equal(bm.isBlocked('198.51.100.1', now), true);
      const info = bm.getBlockInfo('198.51.100.1', now + 1000);
      assert.equal(info.ip, '198.51.100.1');
      assert.equal(info.remainingMs, 599000);

      // Unblock
      const unblocked = bm.unblock('198.51.100.1');
      assert.equal(unblocked, true);
      assert.equal(bm.isBlocked('198.51.100.1', now), false);
    });

    test('normalizes IPv6 casing and mapped IPv4 so block/lookup/unblock match regardless of case', () => {
      const bm = new BlockManager();

      // Block with uppercase IPv6
      bm.block('2001:0DB8:85A3:0000:0000:8A2E:0370:7334', '10m', 'Case test');
      assert.equal(bm.isBlocked('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), true);
      assert.ok(bm.getBlockInfo('2001:0db8:85a3:0000:0000:8a2e:0370:7334') !== null);

      // Unblock with lowercase
      assert.equal(bm.unblock('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), true);
      assert.equal(bm.isBlocked('2001:0DB8:85A3:0000:0000:8A2E:0370:7334'), false);

      // IPv4-mapped IPv6 uppercase
      bm.block('::FFFF:192.0.2.1', '10m');
      assert.equal(bm.isBlocked('192.0.2.1'), true);
      assert.equal(bm.isBlocked('::ffff:192.0.2.1'), true);
    });

    test('RFC 5952 IPv6 canonicalization handles compressed, expanded, leading zeros, and tie-breaking', () => {
      // Compressed and expanded
      assert.equal(canonicalizeIpv6('2001:db8::1'), '2001:db8::1');
      assert.equal(canonicalizeIpv6('2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
      assert.equal(canonicalizeIpv6('2001:DB8:0:0:0:0:0:1'), '2001:db8::1');

      // Leading zeros in hextets
      assert.equal(canonicalizeIpv6('2001:0001:0002:0003:0004:0005:0006:0007'), '2001:1:2:3:4:5:6:7');

      // RFC 5952 rule: single 16-bit 0 field must NOT be compressed
      assert.equal(canonicalizeIpv6('2001:db8:0:1:1:1:1:1'), '2001:db8:0:1:1:1:1:1');

      // RFC 5952 rule: longest zero run wins
      assert.equal(canonicalizeIpv6('2001:db8:0:0:0:1:0:0'), '2001:db8::1:0:0');

      // RFC 5952 rule: first zero run wins on equal length tie
      assert.equal(canonicalizeIpv6('2001:db8:0:0:1:0:0:1'), '2001:db8::1:0:0:1');

      // Unspecified address
      assert.equal(canonicalizeIpv6('::'), '::');
      assert.equal(canonicalizeIpv6('0:0:0:0:0:0:0:0'), '::');

      // Zone identifier stripping
      assert.equal(canonicalizeIpv6('fe80::1%eth0'), 'fe80::1');
    });

    test('normalizeIp handles IPv6 loopback variants, IPv4-mapped, valid IPv4, and invalid addresses', () => {
      // Loopback variants all normalize to 127.0.0.1
      assert.equal(normalizeIp('::1'), '127.0.0.1');
      assert.equal(normalizeIp('0:0:0:0:0:0:0:1'), '127.0.0.1');
      assert.equal(normalizeIp('0000:0000:0000:0000:0000:0000:0000:0001'), '127.0.0.1');

      // IPv4-mapped IPv6 variants all unmap to clean IPv4
      assert.equal(normalizeIp('::ffff:192.0.2.1'), '192.0.2.1');
      assert.equal(normalizeIp('::FFFF:192.0.2.1'), '192.0.2.1');
      assert.equal(normalizeIp('0:0:0:0:0:ffff:192.0.2.1'), '192.0.2.1');
      assert.equal(normalizeIp('0000:0000:0000:0000:0000:ffff:192.0.2.1'), '192.0.2.1');

      // IPv4 preserved
      assert.equal(normalizeIp('198.51.100.1'), '198.51.100.1');

      // Invalid IPs preserved safely without throwing or fabricating valid addresses
      assert.equal(normalizeIp('not-an-ip'), 'not-an-ip');
      assert.equal(normalizeIp('2001:db8:::1'), '2001:db8:::1');
      assert.equal(normalizeIp('::g'), '::g');

      // Empty / non-string falls back to 'unknown'
      assert.equal(normalizeIp(''), 'unknown');
      assert.equal(normalizeIp('   '), 'unknown');
      assert.equal(normalizeIp(null), 'unknown');
      assert.equal(normalizeIp(undefined), 'unknown');
    });

    test('regression test: equivalent IPv6 representations share the exact same rate-limit identity', () => {
      const limiter = new RateLimiter({ maxRequests: 3, windowMs: 60000 });
      const now = 100000;

      // Send 2 requests from fully expanded IPv6
      const r1 = limiter.record('2001:0db8:0000:0000:0000:0000:0000:0001', now);
      assert.equal(r1.count, 1);
      assert.equal(r1.isExceeded, false);

      const r2 = limiter.record('2001:0db8:0000:0000:0000:0000:0000:0001', now);
      assert.equal(r2.count, 2);
      assert.equal(r2.isExceeded, false);

      // Send 3rd request from compressed representation -> reaches limit
      const r3 = limiter.record('2001:db8::1', now);
      assert.equal(r3.count, 3);
      assert.equal(r3.isExceeded, false);

      // Send 4th request from uppercase mixed representation -> must be exceeded!
      const r4 = limiter.record('2001:DB8:0:0:0:0:0:1', now);
      assert.equal(r4.count, 4);
      assert.equal(r4.isExceeded, true);
    });

    test('regression test: equivalent IPv6 representations share the exact same block identity', () => {
      const bm = new BlockManager();

      // Block expanded address
      bm.block('2001:0db8:0000:0000:0000:0000:0000:0001', '10m', 'Rate limit block');

      // Query compressed and uppercase representations
      assert.equal(bm.isBlocked('2001:db8::1'), true);
      assert.equal(bm.isBlocked('2001:DB8:0:0:0:0:0:1'), true);
      assert.ok(bm.getBlockInfo('2001:db8::1') !== null);

      // Unblock using compressed representation
      assert.equal(bm.unblock('2001:db8::1'), true);

      // Expanded representation is now also unblocked
      assert.equal(bm.isBlocked('2001:0db8:0000:0000:0000:0000:0000:0001'), false);
    });

    test('IPv6 /64 subnet masking zeroes host bits and preserves special addresses', () => {
      // Global unicast addresses
      assert.equal(maskIpv6Subnet('2001:db8:abcd:12:1:2:3:4'), '2001:db8:abcd:12::/64');
      assert.equal(maskIpv6Subnet('2001:db8::1'), '2001:db8::/64');
      assert.equal(maskIpv6Subnet('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), '2001:db8:85a3::/64');
      assert.equal(maskIpv6Subnet('2001:db8:0:1:2:3:4:5'), '2001:db8:0:1::/64');

      // Already masked input
      assert.equal(maskIpv6Subnet('2001:db8:abcd:12::/64'), '2001:db8:abcd:12::/64');

      // Preserves IPv4
      assert.equal(maskIpv6Subnet('192.168.1.1'), '192.168.1.1');
      assert.equal(maskIpv6Subnet('10.0.0.1'), '10.0.0.1');

      // Preserves loopback
      assert.equal(maskIpv6Subnet('127.0.0.1'), '127.0.0.1');
      assert.equal(maskIpv6Subnet('::1'), '127.0.0.1');

      // Preserves IPv4-mapped IPv6
      assert.equal(maskIpv6Subnet('::ffff:192.168.1.1'), '192.168.1.1');

      // Preserves invalid or non-IP strings
      assert.equal(maskIpv6Subnet('not-an-ip'), 'not-an-ip');
      assert.equal(maskIpv6Subnet(''), 'unknown');
    });

    test('IPv6 addresses within the same /64 prefix share the same rate-limit bucket when enabled', () => {
      // Default: maskIpv6Subnet is true
      const limiter = new RateLimiter({ maxRequests: 3, windowMs: 60000, maskIpv6Subnet: true });
      const now = 200000;

      // 3 different host addresses within the exact same 2001:db8:abcd:12::/64 subnet
      const r1 = limiter.record('2001:db8:abcd:12:1:2:3:1', now);
      assert.equal(r1.count, 1);
      assert.equal(r1.isExceeded, false);

      const r2 = limiter.record('2001:db8:abcd:12:a:b:c:2', now);
      assert.equal(r2.count, 2);
      assert.equal(r2.isExceeded, false);

      const r3 = limiter.record('2001:db8:abcd:12:ffff:0:0:9', now);
      assert.equal(r3.count, 3);
      assert.equal(r3.isExceeded, false);

      // 4th request from another host in the same /64 subnet -> exceeds limit!
      const r4 = limiter.record('2001:db8:abcd:12:0:0:0:1', now);
      assert.equal(r4.count, 4);
      assert.equal(r4.isExceeded, true);

      // A request from a DIFFERENT subnet (e.g. 2001:db8:abcd:99::1) must have an independent bucket
      const rOther = limiter.record('2001:db8:abcd:99::1', now);
      assert.equal(rOther.count, 1);
      assert.equal(rOther.isExceeded, false);
    });

    test('IPv6 addresses track distinct buckets when maskIpv6Subnet is disabled', () => {
      const limiter = new RateLimiter({ maxRequests: 3, windowMs: 60000, maskIpv6Subnet: false });
      const now = 300000;

      // When maskIpv6Subnet is false, host 1 and host 2 each have independent counters
      const r1 = limiter.record('2001:db8:abcd:12:1:2:3:1', now);
      assert.equal(r1.count, 1);

      const r2 = limiter.record('2001:db8:abcd:12:a:b:c:2', now);
      assert.equal(r2.count, 1);
    });

    test('rejects blocking an invalid IP address', () => {
      const bm = new BlockManager();
      assert.throws(() => bm.block('invalid-ip-string'), /Cannot block invalid IP address/);
      assert.throws(() => bm.unblock('invalid-ip-string'), /Cannot unblock invalid IP address/);
    });

    test('automatically expires blocks after duration passes', () => {
      const bm = new BlockManager();
      const now = 10000;
      const durationMs = 5000;

      bm.block('192.0.2.1', durationMs, 'Temporary test block', now);
      assert.equal(bm.isBlocked('192.0.2.1', now + 1000), true);

      // Time advances past expiry (10000 + 5001ms = 15001)
      assert.equal(bm.isBlocked('192.0.2.1', now + durationMs + 1), false);
      assert.equal(bm.getBlockInfo('192.0.2.1', now + durationMs + 1), null);
    });

    test('strictly bounds memory using LRU eviction when maxBlockedIps is reached', () => {
      const bm = new BlockManager({ maxBlockedIps: 3 });
      const now = 10000;

      bm.block('10.0.0.1', 60000, 'block 1', now);
      bm.block('10.0.0.2', 60000, 'block 2', now + 10);
      bm.block('10.0.0.3', 60000, 'block 3', now + 20);

      assert.equal(bm.size, 3);

      // Access 10.0.0.1 again so 10.0.0.2 is oldest
      bm.block('10.0.0.1', 60000, 'block 1 refreshed', now + 30);

      // Add 4th IP
      bm.block('10.0.0.4', 60000, 'block 4', now + 40);

      assert.equal(bm.size, 3);
      // 10.0.0.2 should have been evicted
      assert.equal(bm.isBlocked('10.0.0.2', now + 50), false);
      assert.equal(bm.isBlocked('10.0.0.1', now + 50), true);
      assert.equal(bm.isBlocked('10.0.0.3', now + 50), true);
      assert.equal(bm.isBlocked('10.0.0.4', now + 50), true);
    });

    test('listBlocks returns active blocks and prunes expired ones', () => {
      const bm = new BlockManager();
      const now = 10000;

      bm.block('10.0.0.1', 5000, 'Short block', now);
      bm.block('10.0.0.2', 60000, 'Long block', now);

      const activeAt12s = bm.listBlocks(now + 2000);
      assert.equal(activeAt12s.length, 2);

      // After 6s, 10.0.0.1 has expired
      const activeAt16s = bm.listBlocks(now + 6000);
      assert.equal(activeAt16s.length, 1);
      assert.equal(activeAt16s[0].ip, '10.0.0.2');
    });
  });

  describe('Programmatic Block API on createShield', () => {
    test('exposes block, unblock, isBlocked, and listBlocks methods', () => {
      const shield = createShield({ mode: 'protect' });

      assert.equal(typeof shield.block, 'function');
      assert.equal(typeof shield.unblock, 'function');
      assert.equal(typeof shield.isBlocked, 'function');
      assert.equal(typeof shield.getBlockInfo, 'function');
      assert.equal(typeof shield.listBlocks, 'function');

      shield.block('172.16.0.5', '5m', 'Testing programmatic API');
      assert.equal(shield.isBlocked('172.16.0.5'), true);
      assert.equal(shield.listBlocks().length, 1);

      shield.unblock('172.16.0.5');
      assert.equal(shield.isBlocked('172.16.0.5'), false);
      assert.equal(shield.listBlocks().length, 0);
    });
  });

  describe('Express Middleware Enforcement (Protect Mode)', () => {
    test('returns HTTP 429 and Retry-After when rate limit is exceeded in protect mode', async () => {
      const app = express();
      const shield = createShield({
        mode: 'protect',
        maxRequests: 2,
        windowMs: 60000
      });

      app.use(shield.middleware);

      let handlerCallCount = 0;
      app.get('/api/resource', (req, res) => {
        handlerCallCount++;
        res.json({ message: 'success' });
      });

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // Request 1: allowed (200)
        const res1 = await fetch(`http://127.0.0.1:${port}/api/resource`);
        assert.equal(res1.status, 200);
        assert.equal(handlerCallCount, 1);

        // Request 2: allowed (200)
        const res2 = await fetch(`http://127.0.0.1:${port}/api/resource`);
        assert.equal(res2.status, 200);
        assert.equal(handlerCallCount, 2);

        // Request 3: threshold exceeded! Should be blocked with HTTP 429
        const res3 = await fetch(`http://127.0.0.1:${port}/api/resource`);
        assert.equal(res3.status, 429);
        assert.equal(handlerCallCount, 2); // Handler was NOT called!

        // Verify headers
        assert.equal(res3.headers.get('x-z-shield-protected'), '1');
        assert.equal(res3.headers.get('x-z-shield-mode'), 'protect');
        assert.equal(res3.headers.get('x-z-shield-suspicious'), '1');
        assert.ok(res3.headers.get('retry-after') !== null);
        const retryAfter = parseInt(res3.headers.get('retry-after'), 10);
        assert.ok(retryAfter >= 1 && retryAfter <= 60);

        // Verify JSON response body
        const body = await res3.json();
        assert.equal(body.error, 'Too Many Requests');
        assert.match(body.message, /Request threshold exceeded/);
        assert.equal(body.retryAfter, retryAfter);
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('immediately blocks an IP placed on temporary block list', async () => {
      const app = express();
      const shield = createShield({
        mode: 'protect',
        maxRequests: 50
      });

      // Manually block localhost
      shield.block('127.0.0.1', '10m', 'Manual administrative ban');

      app.use(shield.middleware);
      app.get('/api/test', (req, res) => res.json({ status: 'ok' }));

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // First request is blocked immediately without reaching route handler
        const response = await fetch(`http://127.0.0.1:${port}/api/test`);
        assert.equal(response.status, 429);
        assert.equal(response.headers.get('x-z-shield-blocked'), '1');
        assert.equal(response.headers.get('x-z-shield-reason'), 'Manual administrative ban');

        const retryAfter = parseInt(response.headers.get('retry-after'), 10);
        assert.ok(retryAfter > 0 && retryAfter <= 600);

        const body = await response.json();
        assert.equal(body.error, 'Too Many Requests');
        assert.match(body.message, /temporarily blocked/);

        // Now unblock and verify access is restored immediately
        shield.unblock('127.0.0.1');
        const retryResponse = await fetch(`http://127.0.0.1:${port}/api/test`);
        assert.equal(retryResponse.status, 200);
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('monitor mode allows requests through even when IP is blocked', async () => {
      const app = express();
      const shield = createShield({
        mode: 'monitor',
        maxRequests: 2
      });

      shield.block('127.0.0.1', '10m', 'Manual flag in monitor mode');

      app.use(shield.middleware);
      app.get('/api/test', (req, res) => res.json({ status: 'ok' }));

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        const response = await fetch(`http://127.0.0.1:${port}/api/test`);
        assert.equal(response.status, 200); // Allowed in monitor mode!
        assert.equal(response.headers.get('x-z-shield-blocked'), '1');
        assert.equal(response.headers.get('x-z-shield-suspicious'), '1');
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('autoBlock option automatically blocks IP when rate limit is exceeded', async () => {
      const app = express();
      const shield = createShield({
        mode: 'protect',
        maxRequests: 1,
        autoBlock: true,
        blockDurationMs: 60000
      });

      app.use(shield.middleware);
      app.get('/api/data', (req, res) => res.send('OK'));

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // Request 1: OK
        await fetch(`http://127.0.0.1:${port}/api/data`);
        assert.equal(shield.isBlocked('127.0.0.1'), false);

        // Request 2: exceeds limit -> triggers autoBlock
        const res2 = await fetch(`http://127.0.0.1:${port}/api/data`);
        assert.equal(res2.status, 429);
        assert.equal(shield.isBlocked('127.0.0.1'), true);

        // Request 3: blocked by blockManager
        const res3 = await fetch(`http://127.0.0.1:${port}/api/data`);
        assert.equal(res3.status, 429);
        assert.equal(res3.headers.get('x-z-shield-blocked'), '1');
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('autoBlock with unknown or invalid IP returns 429 without causing HTTP 500', async () => {
      const app = express();
      const shield = createShield({
        mode: 'protect',
        maxRequests: 1,
        autoBlock: true,
        blockDurationMs: 60000
      });

      // Upstream middleware simulating an environment where client IP cannot be determined
      app.use((req, res, next) => {
        Object.defineProperty(req.socket, 'remoteAddress', { value: undefined, configurable: true });
        if (req.connection) {
          Object.defineProperty(req.connection, 'remoteAddress', { value: undefined, configurable: true });
        }
        next();
      });

      app.use(shield.middleware);
      app.get('/api/test-unknown-ip', (req, res) => res.send('OK'));

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // Request 1: OK
        const res1 = await fetch(`http://127.0.0.1:${port}/api/test-unknown-ip`);
        assert.equal(res1.status, 200);

        // Request 2: exceeds limit -> in protect mode with autoBlock: true
        // Should return 429 Too Many Requests, NOT 500 Internal Server Error
        const res2 = await fetch(`http://127.0.0.1:${port}/api/test-unknown-ip`);
        assert.equal(res2.status, 429, 'Should return 429 instead of throwing 500');
        const body2 = await res2.json();
        assert.equal(body2.error, 'Too Many Requests');
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('Unblock Trap regression: shield.unblock(ip) resets rate limiter counters and does not re-block on next request (Express)', async () => {
      const app = express();
      const shield = createShield({
        mode: 'protect',
        maxRequests: 2,
        windowMs: 60000,
        autoBlock: true,
        blockDurationMs: 60000
      });

      app.use(shield.middleware);
      app.get('/api/unblock-test', (req, res) => res.json({ status: 'ok' }));

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // Request 1: OK
        const res1 = await fetch(`http://127.0.0.1:${port}/api/unblock-test`);
        assert.equal(res1.status, 200);

        // Request 2: OK (reaches maxRequests: 2)
        const res2 = await fetch(`http://127.0.0.1:${port}/api/unblock-test`);
        assert.equal(res2.status, 200);

        // Request 3: exceeds rate limit -> returns 429 and auto-blocks 127.0.0.1
        const res3 = await fetch(`http://127.0.0.1:${port}/api/unblock-test`);
        assert.equal(res3.status, 429);
        assert.equal(shield.isBlocked('127.0.0.1'), true);

        // Administrator calls shield.unblock('127.0.0.1')
        const unblocked = shield.unblock('127.0.0.1');
        assert.equal(unblocked, true);
        assert.equal(shield.isBlocked('127.0.0.1'), false);
        // Rate limiter counter must be reset to 0
        assert.equal(shield.rateLimiter.get('127.0.0.1').count, 0);

        // Request 4 (the next request after unblock): must NOT be re-blocked! Must succeed with 200!
        const res4 = await fetch(`http://127.0.0.1:${port}/api/unblock-test`);
        assert.equal(res4.status, 200, 'Request immediately following shield.unblock() must succeed with 200 and not trigger re-block');
        assert.equal(shield.isBlocked('127.0.0.1'), false);
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('Unblock Trap regression: nextShield.unblock(ip) resets rate limiter counters and does not re-block on next request (Next.js)', async () => {
      const shield = createNextShield({
        mode: 'protect',
        maxRequests: 2,
        windowMs: 60000,
        autoBlock: true,
        blockDurationMs: 60000
      });

      const handler = shield.protect(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
      const createReq = () => ({
        url: 'http://localhost/api/test',
        method: 'GET',
        headers: {},
        socket: { remoteAddress: '127.0.0.1' }
      });

      // Request 1: OK
      const res1 = await handler(createReq());
      assert.equal(res1.status, 200);

      // Request 2: OK
      const res2 = await handler(createReq());
      assert.equal(res2.status, 200);

      // Request 3: Exceeds limit -> 429 & autoBlocked
      const res3 = await handler(createReq());
      assert.equal(res3.status, 429);
      assert.equal(shield.isBlocked('127.0.0.1'), true);

      // Admin calls unblock
      const unblocked = shield.unblock('127.0.0.1');
      assert.equal(unblocked, true);
      assert.equal(shield.isBlocked('127.0.0.1'), false);
      assert.equal(shield.rateLimiter.get('127.0.0.1').count, 0);

      // Request 4: Next request must succeed with 200 and not be re-blocked!
      const res4 = await handler(createReq());
      assert.equal(res4.status, 200, 'Next.js request immediately following unblock must succeed');
      assert.equal(shield.isBlocked('127.0.0.1'), false);
    });
  });
});
