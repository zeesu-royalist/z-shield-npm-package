'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { BlockManager, isValidIp, parseDuration } = require('../src/block-manager');
const { createShield, resolveConfig } = require('../src/index');

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

      assert.throws(() => parseDuration(-100), /Block duration must be a positive number/);
      assert.throws(() => parseDuration('forever'), /Invalid duration format/);
      assert.throws(() => parseDuration({}), /Block duration must be a number/);
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
  });
});
