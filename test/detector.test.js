'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { RateLimiter } = require('../dist/rate-limiter');
const { Detector } = require('../dist/detector');
const { createShield, resolveConfig } = require('../dist/index');

describe('Z-Shield Phase 2: Request Detection & Bounded Counters', () => {

  describe('RateLimiter Unit Tests', () => {
    test('increments counter on subsequent requests within the window', () => {
      const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 5 });
      const now = 10000;

      const res1 = limiter.record('1.2.3.4', now);
      assert.equal(res1.count, 1);
      assert.equal(res1.remaining, 4);
      assert.equal(res1.isExceeded, false);
      assert.equal(res1.resetTime, now + 1000);

      const res2 = limiter.record('1.2.3.4', now + 100);
      assert.equal(res2.count, 2);
      assert.equal(res2.remaining, 3);
      assert.equal(res2.isExceeded, false);

      const res3 = limiter.record('1.2.3.4', now + 200);
      assert.equal(res3.count, 3);
      assert.equal(res3.remaining, 2);
      assert.equal(res3.isExceeded, false);
    });

    test('flags isExceeded when threshold is crossed', () => {
      const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 2 });
      const now = 10000;

      limiter.record('1.2.3.4', now); // count: 1
      limiter.record('1.2.3.4', now + 10); // count: 2
      const res3 = limiter.record('1.2.3.4', now + 20); // count: 3 -> exceeded!

      assert.equal(res3.count, 3);
      assert.equal(res3.remaining, 0);
      assert.equal(res3.isExceeded, true);
    });

    test('resets counter and window after windowMs expires', () => {
      const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 2 });
      const now = 10000;

      limiter.record('1.2.3.4', now);
      limiter.record('1.2.3.4', now + 100);

      // Now time advances past windowMs (10000 + 1001ms = 11001)
      const resAfterExpiry = limiter.record('1.2.3.4', now + 1001);
      assert.equal(resAfterExpiry.count, 1);
      assert.equal(resAfterExpiry.remaining, 1);
      assert.equal(resAfterExpiry.isExceeded, false);
      assert.equal(resAfterExpiry.resetTime, 11001 + 1000);
    });

    test('strictly bounds memory using LRU eviction when maxTrackedIps is reached', () => {
      // Create limiter that only holds 3 IPs max
      const limiter = new RateLimiter({ windowMs: 60000, maxRequests: 10, maxTrackedIps: 3 });
      const now = 10000;

      limiter.record('10.0.0.1', now);
      limiter.record('10.0.0.2', now + 10);
      limiter.record('10.0.0.3', now + 20);

      assert.equal(limiter.size, 3);

      // Access 10.0.0.1 again so 10.0.0.2 becomes the least recently used
      limiter.record('10.0.0.1', now + 30);

      // Now introduce a 4th IP -> should evict 10.0.0.2
      limiter.record('10.0.0.4', now + 40);

      assert.equal(limiter.size, 3);
      // 10.0.0.2 was evicted, so checking it returns fresh/untracked state
      const checkEvicted = limiter.get('10.0.0.2', now + 50);
      assert.equal(checkEvicted.count, 0);

      // 10.0.0.1 and 10.0.0.3 should still exist
      assert.equal(limiter.get('10.0.0.1', now + 50).count, 2);
      assert.equal(limiter.get('10.0.0.3', now + 50).count, 1);
    });

    test('refreshing an expired existing IP does not evict an unrelated active IP when at capacity', () => {
      const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 5, maxTrackedIps: 2 });
      const t0 = 1000;

      // Track IP A and IP B at capacity (2 IPs)
      limiter.record('1.1.1.1', t0);      // window expires at 1000 + 1000 = 2000
      limiter.record('2.2.2.2', t0 + 500); // window expires at 1500 + 1000 = 2500

      // Touch IP A again within its window to make IP B the LRU entry in Map
      limiter.record('1.1.1.1', t0 + 600); // Map order: ['2.2.2.2', '1.1.1.1']

      // Advance time to 2100: IP A has expired (2100 >= 2000), but IP B is still active (2100 < 2500)
      // Refreshing IP A must reset IP A's window, but must NOT evict active IP B
      limiter.record('1.1.1.1', t0 + 1100);

      // Verify active IP B was NOT evicted
      const bStatus = limiter.get('2.2.2.2', t0 + 1100);
      assert.equal(bStatus.count, 1, 'Active IP B should not have been evicted');
      assert.equal(limiter.size, 2, 'Limiter size should remain 2');
    });

    test('pruneExpired removes old counters without affecting active ones', () => {
      const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 5 });
      const now = 10000;

      limiter.record('active-ip', now + 500); // expires at 11500
      limiter.record('expired-ip', now); // expires at 11000

      assert.equal(limiter.size, 2);

      // At 11100, 'expired-ip' is expired, but 'active-ip' is still active
      const pruned = limiter.pruneExpired(11100);
      assert.equal(pruned, 1);
      assert.equal(limiter.size, 1);
      assert.equal(limiter.get('active-ip', 11100).count, 1);
      assert.equal(limiter.get('expired-ip', 11100).count, 0);
    });

    test('ensures two limiter instances maintain independent state', () => {
      const limiterA = new RateLimiter({ maxRequests: 5 });
      const limiterB = new RateLimiter({ maxRequests: 10 });

      limiterA.record('1.1.1.1');
      limiterA.record('1.1.1.1');

      assert.equal(limiterA.get('1.1.1.1').count, 2);
      assert.equal(limiterB.get('1.1.1.1').count, 0);
    });

    test('normalizes IPv6 casing so uppercase and lowercase addresses share counters', () => {
      const limiter = new RateLimiter({ maxRequests: 5 });

      limiter.record('2001:0DB8::1');
      assert.equal(limiter.get('2001:0db8::1').count, 1);

      limiter.record('2001:0db8::1');
      assert.equal(limiter.get('2001:0DB8::1').count, 2);

      limiter.reset('2001:0DB8::1');
      assert.equal(limiter.get('2001:0db8::1').count, 0);
    });

    test('clears all tracked IP records from memory with clear()', () => {
      const limiter = new RateLimiter({ maxRequests: 5 });

      limiter.record('1.1.1.1');
      limiter.record('2.2.2.2');
      limiter.record('3.3.3.3');

      assert.equal(limiter.size, 3);
      assert.equal(limiter.get('1.1.1.1').count, 1);
      assert.equal(limiter.get('2.2.2.2').count, 1);
      assert.equal(limiter.get('3.3.3.3').count, 1);

      limiter.clear();

      assert.equal(limiter.size, 0);
      assert.equal(limiter.get('1.1.1.1').count, 0);
      assert.equal(limiter.get('2.2.2.2').count, 0);
      assert.equal(limiter.get('3.3.3.3').count, 0);
    });
  });

  describe('Detector Unit Tests', () => {
    test('returns normal assessment when within threshold', () => {
      const config = resolveConfig({ windowMs: 60000, maxRequests: 5 });
      const limiter = new RateLimiter(config);
      const detector = new Detector({ rateLimiter: limiter, config });

      const result = detector.check('1.2.3.4');
      assert.equal(result.isSuspicious, false);
      assert.equal(result.type, 'normal');
      assert.equal(result.count, 1);
      assert.equal(result.remaining, 4);
      assert.equal(result.reason, null);
    });

    test('returns suspicious assessment with descriptive reason when threshold exceeded', () => {
      const config = resolveConfig({ windowMs: 60000, maxRequests: 2 });
      const limiter = new RateLimiter(config);
      const detector = new Detector({ rateLimiter: limiter, config });

      detector.check('1.2.3.4');
      detector.check('1.2.3.4');
      const suspiciousResult = detector.check('1.2.3.4');

      assert.equal(suspiciousResult.isSuspicious, true);
      assert.equal(suspiciousResult.type, 'rate_limit');
      assert.equal(suspiciousResult.severity, 'warning');
      assert.equal(suspiciousResult.count, 3);
      assert.equal(suspiciousResult.remaining, 0);
      assert.match(suspiciousResult.reason, /Request threshold exceeded \(3\/2 in 60s\)/);
    });
  });

  describe('Express Middleware Integration (Monitor Mode)', () => {
    test('tracks requests, sets rate limit headers, and does not block in monitor mode', async () => {
      const app = express();
      const shield = createShield({
        mode: 'monitor',
        maxRequests: 3,
        windowMs: 60000
      });

      app.use(shield.middleware);

      app.get('/api/test', (req, res) => {
        res.json({
          status: 'ok',
          detection: req.zShield.detection
        });
      });

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // Request 1: remaining = 2
        const res1 = await fetch(`http://127.0.0.1:${port}/api/test`);
        assert.equal(res1.status, 200);
        assert.equal(res1.headers.get('x-ratelimit-limit'), '3');
        assert.equal(res1.headers.get('x-ratelimit-remaining'), '2');
        assert.equal(res1.headers.get('x-z-shield-suspicious'), null);

        // Request 2: remaining = 1
        const res2 = await fetch(`http://127.0.0.1:${port}/api/test`);
        assert.equal(res2.status, 200);
        assert.equal(res2.headers.get('x-ratelimit-remaining'), '1');

        // Request 3: remaining = 0
        const res3 = await fetch(`http://127.0.0.1:${port}/api/test`);
        assert.equal(res3.status, 200);
        assert.equal(res3.headers.get('x-ratelimit-remaining'), '0');
        assert.equal(res3.headers.get('x-z-shield-suspicious'), null);

        // Request 4: threshold exceeded! In monitor mode, still HTTP 200, but with warning headers
        const res4 = await fetch(`http://127.0.0.1:${port}/api/test`);
        assert.equal(res4.status, 200); // NOT blocked!
        assert.equal(res4.headers.get('x-ratelimit-remaining'), '0');
        assert.equal(res4.headers.get('x-z-shield-suspicious'), '1');
        assert.match(res4.headers.get('x-z-shield-reason'), /Request threshold exceeded/);

        const body = await res4.json();
        assert.equal(body.detection.isSuspicious, true);
        assert.equal(body.detection.count, 4);
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('excluded routes bypass rate limiting counters', async () => {
      const app = express();
      const shield = createShield({
        mode: 'monitor',
        maxRequests: 2,
        excludeRoutes: ['/health']
      });

      app.use(shield.middleware);

      app.get('/health', (req, res) => res.send('OK'));
      app.get('/api/data', (req, res) => res.send('DATA'));

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // Hitting /health 5 times
        for (let i = 0; i < 5; i++) {
          const resHealth = await fetch(`http://127.0.0.1:${port}/health`);
          assert.equal(resHealth.status, 200);
          assert.equal(resHealth.headers.get('x-ratelimit-limit'), null);
        }

        // Hitting /api/data should still have count = 1
        const resData = await fetch(`http://127.0.0.1:${port}/api/data`);
        assert.equal(resData.headers.get('x-ratelimit-remaining'), '1');
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });
  });
});
