'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const express = require('express');

const { Logger, sanitizeString, sanitizeRoute, sanitizeMethod, stripAnsi } = require('../src/logger');
const { createShield, resolveConfig } = require('../src/index');

describe('Z-Shield Phase 4: Persistent Local JSONL Security Event Logging', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-shield-test-'));
  });

  afterEach(async () => {
    if (tempDir && fs.existsSync(tempDir)) {
      await fs.promises.rm(tempDir, { recursive: true, force: true });
    }
  });

  describe('Sanitization & Security Defenses', () => {
    test('strips ANSI terminal escape codes', () => {
      const injected = '\x1b[31;1mINJECTED_RED\x1b[0m normal';
      assert.equal(stripAnsi(injected), 'INJECTED_RED normal');
    });

    test('sanitizes strings against log injection (newlines, control characters)', () => {
      const dangerous = 'Normal text\r\n{"type":"fake_admin_login","action":"granted"}\x00\x08';
      const cleaned = sanitizeString(dangerous);
      assert.equal(cleaned.includes('\n'), false);
      assert.equal(cleaned.includes('\r'), false);
      assert.equal(cleaned.includes('\x00'), false);
    });

    test('truncates strings to maxLength', () => {
      const longStr = 'A'.repeat(500);
      assert.equal(sanitizeString(longStr, 100).length, 100);
    });

    test('sanitizes routes and methods', () => {
      assert.equal(sanitizeRoute('api/users\n\r'), '/api/users');
      assert.equal(sanitizeMethod('post123'), 'POST');
      assert.equal(sanitizeMethod(''), 'GET');
    });
  });

  describe('JSON Lines Formatting & Sensitive Data Exclusion', () => {
    test('writes valid JSON Lines with exact expected schema', async () => {
      const logger = new Logger({
        logDir: tempDir,
        appName: 'test-app'
      });

      const writeSuccess = await logger.log({
        type: 'rate_limit',
        severity: 'warning',
        ip: '192.168.1.100',
        method: 'POST',
        route: '/api/login',
        reason: 'Threshold exceeded',
        action: 'blocked'
      });

      assert.equal(writeSuccess, true);

      const logFile = path.join(tempDir, 'events.jsonl');
      assert.equal(fs.existsSync(logFile), true);

      const content = fs.readFileSync(logFile, 'utf8');
      assert.ok(content.endsWith('\n'));

      const lines = content.trim().split('\n');
      assert.equal(lines.length, 1);

      const event = JSON.parse(lines[0]);
      assert.equal(event.appName, 'test-app');
      assert.equal(event.type, 'rate_limit');
      assert.equal(event.severity, 'warning');
      assert.equal(event.ip, '192.168.1.100');
      assert.equal(event.method, 'POST');
      assert.equal(event.route, '/api/login');
      assert.equal(event.reason, 'Threshold exceeded');
      assert.equal(event.action, 'blocked');
      assert.ok(typeof event.timestamp === 'string');
    });

    test('strictly excludes passwords, cookies, authorization tokens, and request bodies', async () => {
      const logger = new Logger({ logDir: tempDir });

      await logger.log({
        type: 'login_scan',
        ip: '10.0.0.1',
        route: '/api/login',
        // Attempting to pass sensitive information:
        password: 'SUPER_SECRET_PASSWORD',
        cookie: 'session_id=abcdef123456',
        authorization: 'Bearer secret_jwt_token',
        token: 'secret_token_value',
        body: { username: 'admin', password: 'secretpassword' }
      });

      const logFile = path.join(tempDir, 'events.jsonl');
      const rawContent = fs.readFileSync(logFile, 'utf8');

      // Verify none of the sensitive values exist in the logged text
      assert.equal(rawContent.includes('SUPER_SECRET_PASSWORD'), false);
      assert.equal(rawContent.includes('session_id=abcdef123456'), false);
      assert.equal(rawContent.includes('secret_jwt_token'), false);
      assert.equal(rawContent.includes('secret_token_value'), false);
      assert.equal(rawContent.includes('secretpassword'), false);

      const parsed = JSON.parse(rawContent.trim());
      assert.equal(parsed.password, undefined);
      assert.equal(parsed.cookie, undefined);
      assert.equal(parsed.authorization, undefined);
      assert.equal(parsed.body, undefined);
    });

    test('prevents log line splitting when attacker injects newlines into route', async () => {
      const logger = new Logger({ logDir: tempDir });

      await logger.log({
        ip: '1.2.3.4',
        route: '/api/test\r\n{"forged":"event"}\r\n',
        reason: 'Bad input\nwith newlines\n'
      });

      const logFile = path.join(tempDir, 'events.jsonl');
      const rawContent = fs.readFileSync(logFile, 'utf8');

      // There must be exactly ONE line of text
      const lines = rawContent.trim().split('\n');
      assert.equal(lines.length, 1);

      // And it must parse as a single valid JSON object
      const parsed = JSON.parse(lines[0]);
      assert.equal(parsed.route.includes('\n'), false);
      assert.equal(parsed.reason.includes('\n'), false);
    });
  });

  describe('Log Rotation and Retention Limits', () => {
    test('rotates log file when maxLogSizeBytes is exceeded and enforces retention', async () => {
      const logger = new Logger({
        logDir: tempDir,
        logFilename: 'test-events.jsonl',
        maxLogSizeBytes: 200, // Very small size limit to trigger rapid rotation
        maxLogFiles: 2        // Keep test-events.jsonl, test-events.1.jsonl, test-events.2.jsonl
      });

      // Write 6 events
      for (let i = 1; i <= 6; i++) {
        await logger.log({
          ip: `10.0.0.${i}`,
          route: `/test/${i}`,
          reason: `Event number ${i} with padding text to exceed byte threshold`
        });
      }

      // Check rotated files
      const baseFile = path.join(tempDir, 'test-events.jsonl');
      const rot1 = path.join(tempDir, 'test-events.1.jsonl');
      const rot2 = path.join(tempDir, 'test-events.2.jsonl');
      const rot3 = path.join(tempDir, 'test-events.3.jsonl');

      assert.equal(fs.existsSync(baseFile), true);
      assert.equal(fs.existsSync(rot1), true);
      assert.equal(fs.existsSync(rot2), true);
      // test-events.3.jsonl must NOT exist because maxLogFiles is 2
      assert.equal(fs.existsSync(rot3), false);
    });
  });

  describe('Failure Resilience & Concurrency', () => {
    test('handles filesystem write errors safely without crashing', async () => {
      // Create a directory where the log file is expected to force an EISDIR write error
      const targetFilePath = path.join(tempDir, 'events.jsonl');
      fs.mkdirSync(targetFilePath);

      let capturedError = null;
      const logger = new Logger({
        logDir: tempDir,
        logFilename: 'events.jsonl',
        onLogError: (err) => {
          capturedError = err;
        }
      });

      // Should return false and not throw an unhandled rejection
      const result = await logger.log({ ip: '1.1.1.1' });
      assert.equal(result, false);
      assert.ok(capturedError !== null);
      assert.equal(capturedError.code, 'EISDIR');
    });

    test('handles 20 concurrent log writes without record corruption', async () => {
      const logger = new Logger({ logDir: tempDir });

      const promises = [];
      for (let i = 0; i < 20; i++) {
        promises.push(logger.log({
          ip: `192.168.0.${i}`,
          reason: `Concurrent write ${i}`
        }));
      }

      const results = await Promise.all(promises);
      assert.equal(results.every(r => r === true), true);

      const logFile = path.join(tempDir, 'events.jsonl');
      const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
      assert.equal(lines.length, 20);

      // Verify every single line is valid JSON
      lines.forEach((line) => {
        const obj = JSON.parse(line);
        assert.ok(obj.ip.startsWith('192.168.0.'));
      });
    });
  });

  describe('Express Middleware Logging Integration', () => {
    test('logs rate limit block in protect mode', async () => {
      const app = express();
      const shield = createShield({
        logDir: tempDir,
        mode: 'protect',
        maxRequests: 2,
        windowMs: 60000
      });

      app.use(shield.middleware);
      app.get('/api/protected', (req, res) => res.send('OK'));

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        // Request 1: 200 (allowed, no violation)
        await fetch(`http://127.0.0.1:${port}/api/protected`);
        // Request 2: 200 (allowed)
        await fetch(`http://127.0.0.1:${port}/api/protected`);

        // Request 3: 429 (rate limit exceeded -> logged as blocked)
        const res3 = await fetch(`http://127.0.0.1:${port}/api/protected`);
        assert.equal(res3.status, 429);

        // Allow queue microtask to flush
        await new Promise(r => setTimeout(r, 50));

        const logFile = path.join(tempDir, 'events.jsonl');
        assert.equal(fs.existsSync(logFile), true);

        const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
        assert.equal(lines.length, 1);

        const event = JSON.parse(lines[0]);
        assert.equal(event.type, 'rate_limit');
        assert.equal(event.action, 'blocked');
        assert.equal(event.severity, 'warning');
        assert.match(event.reason, /Request threshold exceeded/);
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('logs rate limit warning in monitor mode without blocking', async () => {
      const app = express();
      const shield = createShield({
        logDir: tempDir,
        mode: 'monitor',
        maxRequests: 1,
        windowMs: 60000
      });

      app.use(shield.middleware);
      app.get('/api/monitor', (req, res) => res.send('OK'));

      const server = http.createServer(app);
      await new Promise(resolve => server.listen(0, resolve));
      const port = server.address().port;

      try {
        await fetch(`http://127.0.0.1:${port}/api/monitor`);
        const res2 = await fetch(`http://127.0.0.1:${port}/api/monitor`);
        assert.equal(res2.status, 200); // Not blocked in monitor mode!

        await new Promise(r => setTimeout(r, 50));

        const logFile = path.join(tempDir, 'events.jsonl');
        assert.equal(fs.existsSync(logFile), true);

        const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
        assert.equal(lines.length, 1);

        const event = JSON.parse(lines[0]);
        assert.equal(event.action, 'warned');
      } finally {
        await new Promise(resolve => server.close(resolve));
      }
    });

    test('logs programmatic manual block and unblock operations', async () => {
      const shield = createShield({ logDir: tempDir });

      shield.block('198.51.100.5', '10m', 'Manual administrative block');
      shield.unblock('198.51.100.5');

      await new Promise(r => setTimeout(r, 50));

      const logFile = path.join(tempDir, 'events.jsonl');
      assert.equal(fs.existsSync(logFile), true);

      const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
      assert.equal(lines.length, 2);

      const blockEvent = JSON.parse(lines[0]);
      assert.equal(blockEvent.type, 'manual_block');
      assert.equal(blockEvent.action, 'blocked');
      assert.equal(blockEvent.ip, '198.51.100.5');

      const unblockEvent = JSON.parse(lines[1]);
      assert.equal(unblockEvent.type, 'manual_unblock');
      assert.equal(unblockEvent.action, 'unblocked');
      assert.equal(unblockEvent.ip, '198.51.100.5');
    });
  });
});
