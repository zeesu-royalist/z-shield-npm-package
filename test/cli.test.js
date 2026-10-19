'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const {
  parseCliArgs,
  formatLogEvent,
  readLogs,
  calculateStatus,
  resolveLogPath,
  runCommand
} = require('../src/cli');

describe('Z-Shield Phase 5: CLI Commands & Architecture', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-shield-cli-test-'));
  });

  afterEach(async () => {
    if (tempDir && fs.existsSync(tempDir)) {
      await fs.promises.rm(tempDir, { recursive: true, force: true });
    }
  });

  describe('Argument Parsing', () => {
    test('parses command and flags correctly', () => {
      const parsed1 = parseCliArgs(['status']);
      assert.equal(parsed1.command, 'status');

      const parsed2 = parseCliArgs(['logs', '--limit', '50', '--log-dir', './my-logs']);
      assert.equal(parsed2.command, 'logs');
      assert.equal(parsed2.options.limit, '50');
      assert.equal(parsed2.options['log-dir'], './my-logs');

      const parsed3 = parseCliArgs(['block', '192.168.1.5', '--duration', '10m', '--reason', 'Brute force']);
      assert.equal(parsed3.command, 'block');
      assert.deepEqual(parsed3.args, ['192.168.1.5']);
      assert.equal(parsed3.options.duration, '10m');
      assert.equal(parsed3.options.reason, 'Brute force');
    });

    test('defaults to help on --help or -h flag', () => {
      const parsed = parseCliArgs(['status', '--help']);
      assert.equal(parsed.command, 'help');
    });
  });

  describe('Terminal Sanitization (Anti-Injection)', () => {
    test('strips ANSI color escapes and control characters before formatting', () => {
      const hostileEvent = {
        timestamp: '2026-10-19T12:00:00.000Z',
        severity: '\x1b[31;1mCRITICAL\x1b[0m',
        action: 'blocked',
        ip: '127.0.0.1\x1b[2J',
        method: 'POST\r\n',
        route: '/api/v1/login\x1b[32m',
        reason: 'Threshold exceeded\nInjected text'
      };

      const line = formatLogEvent(hostileEvent);
      assert.equal(line.includes('\x1b['), false);
      assert.equal(line.includes('\n'), false);
      assert.equal(line.includes('\r'), false);
      assert.ok(line.includes('127.0.0.1'));
      assert.ok(line.includes('/api/v1/login'));
    });
  });

  describe('Log Reading & Status Calculation', () => {
    test('handles missing log file gracefully', () => {
      const nonExistentFile = path.join(tempDir, 'does-not-exist.jsonl');
      const res = readLogs(nonExistentFile);
      assert.equal(res.fileExists, false);
      assert.equal(res.events.length, 0);

      const status = calculateStatus(nonExistentFile);
      assert.equal(status.fileExists, false);
      assert.equal(status.totalEvents, 0);
    });

    test('skips malformed JSON lines without crashing and reports count', () => {
      const logFile = path.join(tempDir, 'test-events.jsonl');
      const sample = [
        JSON.stringify({ ip: '1.1.1.1', type: 'rate_limit', action: 'blocked', route: '/a' }),
        '{ this is corrupt JSON line }',
        JSON.stringify({ ip: '2.2.2.2', type: 'rate_limit', action: 'blocked', route: '/b' }),
        'broken',
        JSON.stringify({ ip: '1.1.1.1', type: 'blocked_ip', action: 'blocked', route: '/a' })
      ].join('\n') + '\n';

      fs.writeFileSync(logFile, sample, 'utf8');

      const res = readLogs(logFile, 10);
      assert.equal(res.fileExists, true);
      assert.equal(res.events.length, 3);
      assert.equal(res.malformedCount, 2);

      const status = calculateStatus(logFile);
      assert.equal(status.totalEvents, 3);
      assert.equal(status.topIps[0].ip, '1.1.1.1');
      assert.equal(status.topIps[0].count, 2);
    });
  });

  describe('Command Execution & Error Handling', () => {
    function createMockOutput() {
      const logs = [];
      const errors = [];
      return {
        log: (msg) => logs.push(String(msg)),
        error: (msg) => errors.push(String(msg)),
        getStdout: () => logs.join('\n'),
        getStderr: () => errors.join('\n')
      };
    }

    test('help command prints usage and returns 0', async () => {
      const mock = createMockOutput();
      const code = await runCommand(['--help'], mock);
      assert.equal(code, 0);
      assert.ok(mock.getStdout().includes('Z-Shield CLI'));
      assert.ok(mock.getStdout().includes('Usage:'));
    });

    test('status command with missing file prints friendly message', async () => {
      const mock = createMockOutput();
      const code = await runCommand(['status', '--log-dir', tempDir], mock);
      assert.equal(code, 0);
      assert.ok(mock.getStdout().includes('No log file found yet'));
    });

    test('logs command rejects invalid --limit', async () => {
      const mock = createMockOutput();
      const code = await runCommand(['logs', '--limit', 'invalid'], mock);
      assert.equal(code, 1);
      assert.ok(mock.getStderr().includes('--limit must be a positive integer'));
    });

    test('block command validates IP and duration', async () => {
      const mock1 = createMockOutput();
      const code1 = await runCommand(['block'], mock1);
      assert.equal(code1, 1);
      assert.ok(mock1.getStderr().includes('Missing IP address'));

      const mock2 = createMockOutput();
      const code2 = await runCommand(['block', 'not-an-ip'], mock2);
      assert.equal(code2, 1);
      assert.ok(mock2.getStderr().includes('Invalid IP address'));

      const mock3 = createMockOutput();
      const code3 = await runCommand(['block', '198.51.100.1', '--duration', 'bad-duration'], mock3);
      assert.equal(code3, 1);
      assert.ok(mock3.getStderr().includes('Invalid duration format'));
    });

    test('block command with valid input explains process-local architecture and logs audit record', async () => {
      const mock = createMockOutput();
      const code = await runCommand(['block', '198.51.100.5', '--duration', '10m', '--log-dir', tempDir], mock);
      assert.equal(code, 0);

      const out = mock.getStdout();
      assert.ok(out.includes('Target IP:  198.51.100.5'));
      assert.ok(out.includes('Process-Local Architecture Notice'));
      assert.ok(out.includes('shield.block(\'198.51.100.5\''));

      // Check audit log was written
      const logFile = path.join(tempDir, 'events.jsonl');
      assert.equal(fs.existsSync(logFile), true);
      const content = fs.readFileSync(logFile, 'utf8');
      assert.ok(content.includes('cli_block_requested'));
    });

    test('unblock command with valid input explains architecture and writes audit entry', async () => {
      const mock = createMockOutput();
      const code = await runCommand(['unblock', '198.51.100.5', '--log-dir', tempDir], mock);
      assert.equal(code, 0);

      const out = mock.getStdout();
      assert.ok(out.includes('shield.unblock(\'198.51.100.5\')'));

      const logFile = path.join(tempDir, 'events.jsonl');
      const content = fs.readFileSync(logFile, 'utf8');
      assert.ok(content.includes('cli_unblock_requested'));
    });
  });

  describe('Child Process Binary Invocation', () => {
    test('executes CLI binary directly using node', () => {
      const cliPath = path.resolve(__dirname, '../src/cli.js');
      const output = execFileSync(process.execPath, [cliPath, '--help'], { encoding: 'utf8' });
      assert.ok(output.includes('Z-Shield CLI'));
      assert.ok(output.includes('npx z-shield status'));
      assert.ok(output.includes('npx z-shield monitor'));
    });
  });
});
