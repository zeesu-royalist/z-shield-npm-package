'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

const { createShield, createMiddleware, resolveConfig, DEFAULT_CONFIG } = require('../src/index');
const { extractClientIp } = require('../src/middleware');

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
  });
});
