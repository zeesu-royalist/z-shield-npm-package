'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const express = require('express');

const { createShield, createMiddleware, resolveConfig, DEFAULT_CONFIG } = require('../dist/index');
const { extractClientIp, isRouteExcluded } = require('../dist/middleware');

describe('Z-Shield Phase 1: Configuration & Middleware Foundation', () => {

  describe('Configuration Validation', () => {
    test('resolves default configuration when no options provided', () => {
      const config = resolveConfig();
      assert.equal(config.appName, 'default-app');
      assert.equal(config.mode, 'monitor');
      assert.equal(config.windowMs, 60000);
      assert.equal(config.maxRequests, 100);
      assert.equal(config.maxTrackedIps, 10000);
      assert.equal(config.trustProxy, false);
      assert.deepEqual(config.excludeRoutes, ['/health', '/favicon.ico']);
      assert.ok(Object.isFrozen(config));
    });

    test('accepts valid custom configuration overrides', () => {
      const custom = {
        appName: 'payment-service',
        mode: 'protect',
        windowMs: 30000,
        maxRequests: 50,
        maxTrackedIps: 500,
        trustProxy: true,
        excludeRoutes: ['/ping', '/metrics']
      };
      const config = resolveConfig(custom);
      assert.equal(config.appName, 'payment-service');
      assert.equal(config.mode, 'protect');
      assert.equal(config.windowMs, 30000);
      assert.equal(config.maxRequests, 50);
      assert.equal(config.maxTrackedIps, 500);
      assert.equal(config.trustProxy, true);
      assert.deepEqual(config.excludeRoutes, ['/ping', '/metrics']);
    });

    test('rejects invalid mode', () => {
      assert.throws(
        () => resolveConfig({ mode: 'super-shield' }),
        /Invalid mode "super-shield"/
      );
    });

    test('rejects negative or non-numeric windowMs, maxRequests, and maxTrackedIps', () => {
      assert.throws(() => resolveConfig({ windowMs: -100 }), /"windowMs" must be a positive number/);
      assert.throws(() => resolveConfig({ windowMs: '100' }), /"windowMs" must be a positive number/);
      assert.throws(() => resolveConfig({ maxRequests: 0 }), /"maxRequests" must be a positive integer/);
      assert.throws(() => resolveConfig({ maxRequests: 1.5 }), /"maxRequests" must be a positive integer/);
      assert.throws(() => resolveConfig({ maxTrackedIps: -10 }), /"maxTrackedIps" must be a positive integer/);
      assert.throws(() => resolveConfig({ maxTrackedIps: '500' }), /"maxTrackedIps" must be a positive integer/);
    });

    test('rejects unsafe appName with path traversal characters', () => {
      assert.throws(() => resolveConfig({ appName: '../bad' }), /"appName" can only contain letters/);
      assert.throws(() => resolveConfig({ appName: 'my app with spaces' }), /"appName" can only contain letters/);
      assert.throws(() => resolveConfig({ appName: '' }), /"appName" must be a non-empty string/);
    });

    test('rejects non-boolean trustProxy', () => {
      assert.throws(() => resolveConfig({ trustProxy: 'yes' }), /"trustProxy" must be a boolean/);
    });

    test('resolves logDir to an absolute path for default and relative paths (P4 regression)', () => {
      const defaultConfig = resolveConfig();
      assert.equal(defaultConfig.logDir, path.resolve(process.cwd(), '.z-shield-logs'));
      assert.ok(path.isAbsolute(defaultConfig.logDir));

      const relativeConfig = resolveConfig({ logDir: './custom-logs' });
      assert.equal(relativeConfig.logDir, path.resolve('./custom-logs'));
      assert.ok(path.isAbsolute(relativeConfig.logDir));

      assert.throws(() => resolveConfig({ logDir: '' }), /"logDir" must be a non-empty string path/);
      assert.throws(() => resolveConfig({ logDir: 123 }), /"logDir" must be a non-empty string path/);
    });

    test('validates and parses blockDuration strings and numbers', () => {
      const cfg1 = resolveConfig({ blockDuration: '10m' });
      assert.equal(cfg1.blockDurationMs, 600000);

      const cfg2 = resolveConfig({ blockDuration: '30s' });
      assert.equal(cfg2.blockDurationMs, 30000);

      const cfg3 = resolveConfig({ blockDuration: '1h' });
      assert.equal(cfg3.blockDurationMs, 3600000);

      const cfg4 = resolveConfig({ blockDuration: 5000 });
      assert.equal(cfg4.blockDurationMs, 5000);

      assert.throws(() => resolveConfig({ blockDuration: '0s' }), /Block duration must be greater than zero/);
      assert.throws(() => resolveConfig({ blockDuration: 0 }), /Block duration must be a positive number/);
      assert.throws(() => resolveConfig({ blockDuration: -100 }), /Block duration must be a positive number/);
      assert.throws(() => resolveConfig({ blockDuration: 'invalid' }), /Invalid duration format/);
      assert.throws(() => resolveConfig({ blockDuration: {} }), /Block duration must be a number/);
    });

    test('validates excludeRoutes strictly and rejects invalid elements', () => {
      assert.throws(() => resolveConfig({ excludeRoutes: '/health' }), /"excludeRoutes" must be an array/);
      assert.throws(() => resolveConfig({ excludeRoutes: ['/health', 123] }), /"excludeRoutes" must be an array/);
      assert.throws(() => resolveConfig({ excludeRoutes: ['/health', ''] }), /"excludeRoutes" must be an array of non-empty string/);
      assert.throws(() => resolveConfig({ excludeRoutes: ['/health', '   '] }), /"excludeRoutes" must be an array of non-empty string/);
      assert.throws(() => resolveConfig({ excludeRoutes: null }), /"excludeRoutes" must be an array/);
    });

    test('validates logFilename and prevents directory traversal', () => {
      const valid = resolveConfig({ logFilename: 'custom.jsonl' });
      assert.equal(valid.logFilename, 'custom.jsonl');

      assert.throws(() => resolveConfig({ logFilename: '' }), /"logFilename" must be a non-empty string/);
      assert.throws(() => resolveConfig({ logFilename: '../events.jsonl' }), /safe filename without path traversal/);
      assert.throws(() => resolveConfig({ logFilename: 'dir/events.jsonl' }), /safe filename without path traversal/);
      assert.throws(() => resolveConfig({ logFilename: 'dir\\events.jsonl' }), /safe filename without path traversal/);
      assert.throws(() => resolveConfig({ logFilename: 123 }), /"logFilename" must be a non-empty string/);
    });

    test('validates maxBlockedIps, maxLogSizeBytes, maxLogFiles, and onLogError boundary cases', () => {
      // maxBlockedIps
      assert.throws(() => resolveConfig({ maxBlockedIps: 0 }), /"maxBlockedIps" must be a positive integer/);
      assert.throws(() => resolveConfig({ maxBlockedIps: -5 }), /"maxBlockedIps" must be a positive integer/);
      assert.throws(() => resolveConfig({ maxBlockedIps: 1.5 }), /"maxBlockedIps" must be a positive integer/);

      // maxLogSizeBytes
      assert.throws(() => resolveConfig({ maxLogSizeBytes: 0 }), /"maxLogSizeBytes" must be a positive integer/);
      assert.throws(() => resolveConfig({ maxLogSizeBytes: -100 }), /"maxLogSizeBytes" must be a positive integer/);
      assert.throws(() => resolveConfig({ maxLogSizeBytes: 1.5 }), /"maxLogSizeBytes" must be a positive integer/);

      // maxLogFiles
      assert.throws(() => resolveConfig({ maxLogFiles: -1 }), /"maxLogFiles" must be a non-negative integer/);
      assert.throws(() => resolveConfig({ maxLogFiles: 1.5 }), /"maxLogFiles" must be a non-negative integer/);
      const zeroFiles = resolveConfig({ maxLogFiles: 0 });
      assert.equal(zeroFiles.maxLogFiles, 0);

      // autoBlock
      assert.throws(() => resolveConfig({ autoBlock: 'yes' }), /"autoBlock" must be a boolean/);

      // onLogError
      assert.throws(() => resolveConfig({ onLogError: 'not-a-func' }), /"onLogError" must be null or a function/);
      const withFunc = resolveConfig({ onLogError: () => {} });
      assert.equal(typeof withFunc.onLogError, 'function');
      const withNull = resolveConfig({ onLogError: null });
      assert.equal(withNull.onLogError, null);

      // maxLogQueueSize
      assert.throws(() => resolveConfig({ maxLogQueueSize: -5 }), /"maxLogQueueSize" must be a positive integer/);
      assert.throws(() => resolveConfig({ maxLogQueueSize: 0 }), /"maxLogQueueSize" must be a positive integer/);
      assert.throws(() => resolveConfig({ maxLogQueueSize: 10.5 }), /"maxLogQueueSize" must be a positive integer/);
      const validQueue = resolveConfig({ maxLogQueueSize: 500 });
      assert.equal(validQueue.maxLogQueueSize, 500);
    });

    test('ensures two instances do not share or mutate configuration state', () => {
      const shield1 = createShield({ appName: 'app-one', mode: 'monitor' });
      const shield2 = createShield({ appName: 'app-two', mode: 'protect' });

      assert.equal(shield1.config.appName, 'app-one');
      assert.equal(shield2.config.appName, 'app-two');
      assert.equal(shield1.config.mode, 'monitor');
      assert.equal(shield2.config.mode, 'protect');

      // Check immutability
      assert.throws(() => {
        shield1.config.mode = 'protect';
      });
    });
  });

  describe('Client IP Extraction & Security', () => {
    test('extracts remoteAddress from socket when trustProxy is false', () => {
      const fakeReq = {
        headers: { 'x-forwarded-for': '203.0.113.195' }, // spoofed header
        socket: { remoteAddress: '198.51.100.1' },
        ip: '203.0.113.195'
      };

      // With trustProxy false, spoofed header is ignored in favor of the real socket IP
      const ip = extractClientIp(fakeReq, false);
      assert.equal(ip, '198.51.100.1');
    });

    test('uses req.ip when trustProxy is true', () => {
      const fakeReq = {
        socket: { remoteAddress: '10.0.0.1' },
        ip: '203.0.113.195'
      };

      const ip = extractClientIp(fakeReq, true);
      assert.equal(ip, '203.0.113.195');
    });

    test('normalizes IPv6-mapped IPv4 addresses', () => {
      const fakeReq = {
        socket: { remoteAddress: '::ffff:192.168.1.10' }
      };

      const ip = extractClientIp(fakeReq, false);
      assert.equal(ip, '192.168.1.10');
    });

    test('normalizes IPv6 localhost to 127.0.0.1', () => {
      const fakeReq = {
        socket: { remoteAddress: '::1' }
      };

      const ip = extractClientIp(fakeReq, false);
      assert.equal(ip, '127.0.0.1');
    });

    test('normalizes uppercase IPv6 and uppercase IPv4-mapped IPv6 addresses', () => {
      const fakeMapped = { socket: { remoteAddress: '::FFFF:192.168.1.50' } };
      assert.equal(extractClientIp(fakeMapped, false), '192.168.1.50');

      const fakeIpv6 = { socket: { remoteAddress: '2001:0DB8:85A3:0000:0000:8A2E:0370:7334' } };
      assert.equal(extractClientIp(fakeIpv6, false), '2001:db8:85a3::8a2e:370:7334');
    });
  });

  describe('Express Middleware Integration', () => {
    test('passes requests through and sets headers in a live Express server', async () => {
      const app = express();
      const shield = createShield({ mode: 'monitor', appName: 'test-app' });

      app.use(shield.middleware);

      app.get('/api/test', (req, res) => {
        res.json({
          message: 'ok',
          zShield: req.zShield
        });
      });

      // Start test server on random free port
      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        const response = await fetch(`http://127.0.0.1:${port}/api/test`);
        assert.equal(response.status, 200);

        // Check headers
        assert.equal(response.headers.get('x-z-shield-protected'), '1');
        assert.equal(response.headers.get('x-z-shield-mode'), 'monitor');

        const body = await response.json();
        assert.equal(body.message, 'ok');
        assert.equal(body.zShield.appName, 'test-app');
        assert.equal(body.zShield.mode, 'monitor');
        assert.equal(body.zShield.ip, '127.0.0.1');
        assert.equal(body.zShield.isExcluded, false);
        assert.ok(typeof body.zShield.startTime === 'number');
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('flags excluded routes properly without crashing', async () => {
      const app = express();
      const shield = createShield({
        mode: 'protect',
        excludeRoutes: ['/health']
      });

      app.use(shield.middleware);

      app.get('/health', (req, res) => {
        res.json({ status: 'healthy', isExcluded: req.zShield.isExcluded });
      });

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        const response = await fetch(`http://127.0.0.1:${port}/health`);
        assert.equal(response.status, 200);

        const body = await response.json();
        assert.equal(body.status, 'healthy');
        assert.equal(body.isExcluded, true);
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('route exclusion matching respects path-segment boundaries and query strings', async () => {
      const app = express();
      const shield = createShield({
        mode: 'protect',
        excludeRoutes: ['/health', '/status/']
      });

      app.use(shield.middleware);

      app.get('/health', (req, res) => res.json({ route: '/health', isExcluded: req.zShield.isExcluded }));
      app.get('/health/live', (req, res) => res.json({ route: '/health/live', isExcluded: req.zShield.isExcluded }));
      app.get('/health-check', (req, res) => res.json({ route: '/health-check', isExcluded: req.zShield.isExcluded }));
      app.get('/healthcare', (req, res) => res.json({ route: '/healthcare', isExcluded: req.zShield.isExcluded }));
      app.get('/status', (req, res) => res.json({ route: '/status', isExcluded: req.zShield.isExcluded }));
      app.get('/status/ready', (req, res) => res.json({ route: '/status/ready', isExcluded: req.zShield.isExcluded }));
      app.get('/status-page', (req, res) => res.json({ route: '/status-page', isExcluded: req.zShield.isExcluded }));

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // Excluded: exact match
        const resHealth = await fetch(`http://127.0.0.1:${port}/health?query=1`);
        const bodyHealth = await resHealth.json();
        assert.equal(bodyHealth.isExcluded, true, '/health should be excluded');

        // Excluded: sub-segment match
        const resHealthLive = await fetch(`http://127.0.0.1:${port}/health/live`);
        const bodyHealthLive = await resHealthLive.json();
        assert.equal(bodyHealthLive.isExcluded, true, '/health/live should be excluded');

        // Excluded: prefix defined with trailing slash
        const resStatus = await fetch(`http://127.0.0.1:${port}/status`);
        const bodyStatus = await resStatus.json();
        assert.equal(bodyStatus.isExcluded, true, '/status should be excluded');

        const resStatusReady = await fetch(`http://127.0.0.1:${port}/status/ready`);
        const bodyStatusReady = await resStatusReady.json();
        assert.equal(bodyStatusReady.isExcluded, true, '/status/ready should be excluded');

        // NOT excluded: boundary breach (must NOT match prefix that is not a boundary)
        const resHealthCheck = await fetch(`http://127.0.0.1:${port}/health-check`);
        const bodyHealthCheck = await resHealthCheck.json();
        assert.equal(bodyHealthCheck.isExcluded, false, '/health-check must NOT be excluded');

        const resHealthCare = await fetch(`http://127.0.0.1:${port}/healthcare`);
        const bodyHealthCare = await resHealthCare.json();
        assert.equal(bodyHealthCare.isExcluded, false, '/healthcare must NOT be excluded');

        const resStatusPage = await fetch(`http://127.0.0.1:${port}/status-page`);
        const bodyStatusPage = await resStatusPage.json();
        assert.equal(bodyStatusPage.isExcluded, false, '/status-page must NOT be excluded');
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('isRouteExcluded handles consecutive redundant slashes (//health, /health///live)', () => {
      const excluded = ['/health', '/status/'];

      // Consecutive leading slashes
      assert.equal(isRouteExcluded('//health', excluded), true);
      assert.equal(isRouteExcluded('///health', excluded), true);
      assert.equal(isRouteExcluded('////health', excluded), true);

      // Consecutive intermediate slashes
      assert.equal(isRouteExcluded('/health///live', excluded), true);
      assert.equal(isRouteExcluded('//health//ready', excluded), true);
      assert.equal(isRouteExcluded('/status///ready', excluded), true);

      // Trailing consecutive slashes
      assert.equal(isRouteExcluded('/health//', excluded), true);
      assert.equal(isRouteExcluded('//health//', excluded), true);

      // Consecutive slashes with query string and fragment
      assert.equal(isRouteExcluded('//health///live?check=1#top', excluded), true);

      // Root slash with redundant slashes
      assert.equal(isRouteExcluded('///', ['/']), true);
      assert.equal(isRouteExcluded('//', ['/']), true);

      // Boundary safety check: consecutive slashes must NOT match non-boundary routes
      assert.equal(isRouteExcluded('//healthcare', excluded), false);
      assert.equal(isRouteExcluded('///health-check', excluded), false);
      assert.equal(isRouteExcluded('//status-page', excluded), false);

      // Exclude route defined with redundant slashes
      assert.equal(isRouteExcluded('/health', ['//health']), true);
      assert.equal(isRouteExcluded('/health/live', ['//health//']), true);
    });

    test('handles request safely when headers have already been sent by upstream middleware', async () => {
      const app = express();
      const shield = createShield({ mode: 'protect', maxRequests: 5 });

      // Upstream middleware commits headers early (e.g. streaming response)
      app.use((req, res, next) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        next();
      });

      app.use(shield.middleware);

      app.get('/api/stream', (req, res) => {
        res.end(JSON.stringify({ status: 'ok', protected: req.zShield ? true : false }));
      });

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        const response = await fetch(`http://127.0.0.1:${port}/api/stream`);
        assert.equal(response.status, 200);
        const data = await response.json();
        assert.equal(data.protected, true);
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('safely terminates open response without hanging when rate limit is exceeded and headers were flushed upstream', async () => {
      const app = express();
      const shield = createShield({ mode: 'protect', maxRequests: 1 });

      let downstreamCallCount = 0;

      // Upstream middleware commits headers early (e.g. streaming or chunked pipeline)
      app.use((req, res, next) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        next();
      });

      app.use(shield.middleware);

      app.get('/api/stream-rate-limited', (req, res) => {
        downstreamCallCount++;
        res.end('payload');
      });

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // Request 1: allowed, downstream handler runs
        const res1 = await fetch(`http://127.0.0.1:${port}/api/stream-rate-limited`, {
          signal: AbortSignal.timeout(2000)
        });
        assert.equal(res1.status, 200);
        assert.equal(downstreamCallCount, 1);

        // Request 2: rate limit exceeded in protect mode!
        // Headers were committed upstream as 200, so Z-Shield cannot send 429 JSON.
        // It must safely end the open response stream without hanging, and without calling downstream.
        const res2 = await fetch(`http://127.0.0.1:${port}/api/stream-rate-limited`, {
          signal: AbortSignal.timeout(2000)
        });
        assert.equal(res2.status, 200);
        await res2.text(); // Successfully reads EOF without hanging
        assert.equal(downstreamCallCount, 1, 'Downstream handler should not have been called for rate-limited request');
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('safely terminates open response without hanging when IP is already blocked and headers were flushed upstream', async () => {
      const app = express();
      const shield = createShield({ mode: 'protect' });

      // Block client IP in advance
      shield.block('127.0.0.1', '10m', 'Pre-blocked test IP');

      let downstreamCalled = false;

      // Upstream middleware commits headers early
      app.use((req, res, next) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        next();
      });

      app.use(shield.middleware);

      app.get('/api/stream-already-blocked', (req, res) => {
        downstreamCalled = true;
        res.end('payload');
      });

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        const response = await fetch(`http://127.0.0.1:${port}/api/stream-already-blocked`, {
          signal: AbortSignal.timeout(2000)
        });
        assert.equal(response.status, 200);
        await response.text(); // Reads EOF without hanging
        assert.equal(downstreamCalled, false, 'Downstream handler should not have been called for blocked IP');
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });
  });
});
