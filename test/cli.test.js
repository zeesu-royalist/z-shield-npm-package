'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const {
  createColors,
  resolveColorSupport,
  parseCliArgs,
  formatLogEvent,
  readLogs,
  calculateStatus,
  resolveLogPath,
  runCommand,
  sanitizeIp,
  sanitizeType,
  sanitizeAction
} = require('../dist/cli');
const { stripAnsi } = require('../dist/logger');

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

    test('resolves log file path to an absolute path for default and custom options', () => {
      const defaultLog = resolveLogPath();
      assert.equal(defaultLog, path.join(process.cwd(), '.z-shield-logs', 'events.jsonl'));
      assert.ok(path.isAbsolute(defaultLog));

      const relativeLog = resolveLogPath({ 'log-dir': './custom-logs' });
      assert.equal(relativeLog, path.join(path.resolve('./custom-logs'), 'events.jsonl'));
      assert.ok(path.isAbsolute(relativeLog));
    });

    test('supports Z_SHIELD_LOG_DIR environment variable with proper precedence', () => {
      const originalEnv = process.env.Z_SHIELD_LOG_DIR;
      try {
        // 1. Z_SHIELD_LOG_DIR env var used when no CLI option given
        process.env.Z_SHIELD_LOG_DIR = '/var/log/z-shield';
        const envLog = resolveLogPath();
        assert.equal(envLog, path.join(path.resolve('/var/log/z-shield'), 'events.jsonl'));

        // 2. CLI option --log-dir takes precedence over Z_SHIELD_LOG_DIR
        const cliLog = resolveLogPath({ 'log-dir': './cli-override' });
        assert.equal(cliLog, path.join(path.resolve('./cli-override'), 'events.jsonl'));

        // 3. Empty or whitespace Z_SHIELD_LOG_DIR falls back to default
        process.env.Z_SHIELD_LOG_DIR = '   ';
        const fallbackLog = resolveLogPath();
        assert.equal(fallbackLog, path.join(process.cwd(), '.z-shield-logs', 'events.jsonl'));
      } finally {
        if (originalEnv !== undefined) {
          process.env.Z_SHIELD_LOG_DIR = originalEnv;
        } else {
          delete process.env.Z_SHIELD_LOG_DIR;
        }
      }
    });

    test('strictly validates --log-file and rejects path traversal attempts', () => {
      // Valid custom filenames
      const valid1 = resolveLogPath({ 'log-file': 'custom.jsonl' });
      assert.ok(valid1.endsWith(path.join('.z-shield-logs', 'custom.jsonl')));

      const valid2 = resolveLogPath({ logFile: 'audit_2026.log' });
      assert.ok(valid2.endsWith(path.join('.z-shield-logs', 'audit_2026.log')));

      // Rejects path traversal
      assert.throws(
        () => resolveLogPath({ 'log-file': '../secret.json' }),
        /--log-file.*must be a safe filename without path traversal characters/
      );
      assert.throws(
        () => resolveLogPath({ 'log-file': 'sub/dir.jsonl' }),
        /--log-file.*must be a safe filename without path traversal characters/
      );
      assert.throws(
        () => resolveLogPath({ 'log-file': '..\\windows.jsonl' }),
        /--log-file.*must be a safe filename without path traversal characters/
      );
      assert.throws(
        () => resolveLogPath({ logFile: '/etc/passwd' }),
        /--log-file.*must be a safe filename without path traversal characters/
      );
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

    test('sanitizes untrusted status fields before aggregation and terminal output', async () => {
      const logFile = path.join(tempDir, 'events.jsonl');
      const hostileEvent = {
        ip: '203.0.113.8\u001b[31mINJECTED\u001b[0m',
        route: '/api\nINJECTED\x7f',
        type: 'rate_limit\r\nINJECTED',
        action: 'warned\x1b[2JINJECTED',
        reason: 'secret reason\u001b[HINJECTED',
        severity: 'warning'
      };
      fs.writeFileSync(logFile, `${JSON.stringify(hostileEvent)}\n`, 'utf8');

      const status = calculateStatus(logFile);
      assert.deepEqual(Object.keys(status.typeCounts), ['rate_limit']);
      assert.deepEqual(Object.keys(status.actionCounts), ['warned']);
      assert.deepEqual(status.topIps.map(({ ip }) => ip), ['203.0.113.8']);
      assert.deepEqual(status.topRoutes.map(({ route }) => route), ['/api']);

      const logs = [];
      const output = {
        log: (message) => logs.push(String(message)),
        error: () => {}
      };
      const code = await runCommand(['status', '--no-color', '--log-dir', tempDir], output);
      assert.equal(code, 0);

      const rendered = logs.join('\n');
      assert.doesNotMatch(rendered, /[\x00-\x09\x0b-\x1f\x7f]/);
      assert.doesNotMatch(rendered, /\x1b/);
      assert.doesNotMatch(rendered, /INJECTED/);
      assert.equal(rendered.includes('secret reason'), false);

      const typeSummary = rendered.split('\n').filter((line) => line.includes('rate_limit'));
      assert.equal(typeSummary.length, 1);
      assert.match(typeSummary[0], /rate_limit: 1/);
      const routeSummary = rendered.split('\n').filter((line) => line.includes('/api'));
      assert.equal(routeSummary.length, 1);
      assert.match(routeSummary[0], /\/api: 1 events/);
      const ipSummary = rendered.split('\n').filter((line) => line.includes('203.0.113.8'));
      assert.equal(ipSummary.length, 1);
      assert.match(ipSummary[0], /203\.0\.113\.8: 1 events/);
    });

    test('prevents duplicate aggregation entries from newline splitting in untrusted fields', async () => {
      const logFile = path.join(tempDir, 'events.jsonl');
      const events = [
        {
          ip: '198.51.100.1\u001b[31mBAD\u001b[0m',
          route: '/api\nINJECTED_LINE_1',
          type: 'rate_limit\r\nFAKE',
          action: 'warned',
          severity: 'warning'
        },
        {
          ip: '198.51.100.1',
          route: '/api\r\nINJECTED_LINE_2',
          type: 'rate_limit',
          action: 'warned',
          severity: 'warning'
        },
        {
          ip: '198.51.100.1',
          route: '/api',
          type: 'rate_limit',
          action: 'warn',
          severity: 'warning'
        }
      ];
      fs.writeFileSync(logFile, events.map((e) => JSON.stringify(e)).join('\n') + '\n', 'utf8');

      const status = calculateStatus(logFile);
      assert.equal(status.totalEvents, 3);
      assert.deepEqual(Object.keys(status.typeCounts), ['rate_limit']);
      assert.equal(status.typeCounts.rate_limit, 3);
      assert.deepEqual(Object.keys(status.actionCounts), ['warned']);
      assert.equal(status.actionCounts.warned, 3);
      assert.deepEqual(status.topIps.map(({ ip }) => ip), ['198.51.100.1']);
      assert.equal(status.topIps[0].count, 3);
      assert.deepEqual(status.topRoutes.map(({ route }) => route), ['/api']);
      assert.equal(status.topRoutes[0].count, 3);

      const logs = [];
      const output = {
        log: (message) => logs.push(String(message)),
        error: () => {}
      };
      const code = await runCommand(['status', '--no-color', '--log-dir', tempDir], output);
      assert.equal(code, 0);

      const rendered = logs.join('\n');
      assert.doesNotMatch(rendered, /\x1b/);
      assert.doesNotMatch(rendered, /INJECTED/);
      const routeLines = rendered.split('\n').filter((l) => l.includes('/api'));
      assert.equal(routeLines.length, 1);
      assert.match(routeLines[0], /\/api: 3 events/);
    });

    test('sanitizeIp extracts valid IP addresses and neutralizes injection payloads', () => {
      assert.equal(sanitizeIp('127.0.0.1\u001b[31mINJECTED\u001b[0m'), '127.0.0.1');
      assert.equal(sanitizeIp('\u001b[31m127.0.0.1\u001b[0m'), '127.0.0.1');
      assert.equal(sanitizeIp('192.168.1.1\r\nINJECTED'), '192.168.1.1');
      assert.equal(sanitizeIp('::1'), '127.0.0.1');
      assert.equal(sanitizeIp('::ffff:192.168.1.1'), '192.168.1.1');
      assert.equal(sanitizeIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), '2001:db8:85a3::8a2e:370:7334');
      assert.equal(sanitizeIp('completely-invalid-ip'), 'unknown');
      assert.equal(sanitizeIp(''), 'unknown');
      assert.equal(sanitizeIp(null), 'unknown');
    });

    test('sanitizeType and sanitizeAction strip terminal control sequences and newlines', () => {
      assert.equal(sanitizeType('rate_limit\u001b[2J'), 'rate_limit');
      assert.equal(sanitizeType('rate_limit\r\nINJECTED'), 'rate_limit');
      assert.equal(sanitizeType(''), 'unknown');

      assert.equal(sanitizeAction('warned\x1b[2JINJECTED'), 'warned');
      assert.equal(sanitizeAction('BLOCKED\r\nINJECTED'), 'blocked');
      assert.equal(sanitizeAction(''), 'unknown');
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
      const out = mock.getStdout();
      assert.ok(out.includes('No log file found yet'));
      assert.ok(out.includes('Checked Location:'));
      assert.ok(out.includes(tempDir));
      assert.ok(out.includes('Z_SHIELD_LOG_DIR'));
      assert.ok(out.includes('--log-dir'));
    });

    test('logs command with missing file prints helpful message with path and hints', async () => {
      const mock = createMockOutput();
      const code = await runCommand(['logs', '--log-dir', tempDir], mock);
      assert.equal(code, 0);
      const out = mock.getStdout();
      assert.ok(out.includes('No log file found at:'));
      assert.ok(out.includes(tempDir));
      assert.ok(out.includes('Z_SHIELD_LOG_DIR'));
      assert.ok(out.includes('--log-dir'));
    });

    test('help command documents Z_SHIELD_LOG_DIR environment variable', async () => {
      const mock = createMockOutput();
      const code = await runCommand(['--help'], mock);
      assert.equal(code, 0);
      const out = mock.getStdout();
      assert.ok(out.includes('Z_SHIELD_LOG_DIR'));
      assert.ok(out.includes('--log-dir'));
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

      const mock4 = createMockOutput();
      const code4 = await runCommand(['block', '198.51.100.1', '--duration', '0s'], mock4);
      assert.equal(code4, 1);
      assert.ok(mock4.getStderr().includes('Block duration must be greater than zero'));
    });

    test('block command with valid input explains process-local architecture and logs audit record', async () => {
      const mock = createMockOutput();
      const code = await runCommand(['block', '198.51.100.5', '--duration', '10m', '--log-dir', tempDir], mock);
      assert.equal(code, 0);

      const out = mock.getStdout();
      const cleanOut = stripAnsi(out);
      assert.ok(cleanOut.includes('Target IP:  198.51.100.5'));
      assert.ok(cleanOut.includes('Process-Local Architecture Notice'));
      assert.ok(cleanOut.includes('shield.block(\'198.51.100.5\''));

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
      const cleanOut = stripAnsi(out);
      assert.ok(cleanOut.includes('Target IP:  198.51.100.5'));
      assert.ok(cleanOut.includes('shield.unblock(\'198.51.100.5\')'));

      const logFile = path.join(tempDir, 'events.jsonl');
      const content = fs.readFileSync(logFile, 'utf8');
      assert.ok(content.includes('cli_unblock_requested'));
    });
  });

  describe('Terminal Color Support & Accessibility', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      process.env = { ...originalEnv };
    });

    test('createColors(false) returns plain unstyled strings for all color helpers', () => {
      const colors = createColors(false);
      assert.equal(colors.red('error'), 'error');
      assert.equal(colors.green('ok'), 'ok');
      assert.equal(colors.yellow('warn'), 'warn');
      assert.equal(colors.blue('info'), 'info');
      assert.equal(colors.cyan('path'), 'path');
      assert.equal(colors.gray('time'), 'time');
      assert.equal(colors.bold('title'), 'title');
      assert.equal(colors.dim('sub'), 'sub');
      assert.equal(colors.inverse('badge'), 'badge');
      assert.equal(colors.hasColors, false);
    });

    test('createColors(true) applies standard ANSI escape sequences', () => {
      const colors = createColors(true);
      assert.equal(colors.hasColors, true);
      assert.equal(colors.red('error'), '\x1b[31merror\x1b[39m');
      assert.equal(colors.green('ok'), '\x1b[32mok\x1b[39m');
      assert.equal(colors.yellow('warn'), '\x1b[33mwarn\x1b[39m');
      assert.equal(colors.cyan('path'), '\x1b[36mpath\x1b[39m');
      assert.equal(colors.gray('time'), '\x1b[90mtime\x1b[39m');
      assert.equal(colors.bold('title'), '\x1b[1mtitle\x1b[22m');
    });

    test('resolveColorSupport respects flags, environment variables, and TTY status', () => {
      delete process.env.NO_COLOR;
      delete process.env.NODE_DISABLE_COLORS;
      delete process.env.FORCE_COLOR;

      const ttyOutput = { isTTY: true };
      const nonTtyOutput = { isTTY: false };

      // Explicit --no-color flag disables colors even on TTY
      assert.equal(resolveColorSupport({ 'no-color': true }, ttyOutput), false);
      assert.equal(resolveColorSupport({ color: false }, ttyOutput), false);
      assert.equal(resolveColorSupport({ color: 'false' }, ttyOutput), false);

      // Explicit --color flag forces colors even on non-TTY
      assert.equal(resolveColorSupport({ color: true }, nonTtyOutput), true);
      assert.equal(resolveColorSupport({ color: 'true' }, nonTtyOutput), true);

      // NO_COLOR standard disables colors
      process.env.NO_COLOR = '1';
      assert.equal(resolveColorSupport({}, ttyOutput), false);
      delete process.env.NO_COLOR;

      // NODE_DISABLE_COLORS disables colors
      process.env.NODE_DISABLE_COLORS = '1';
      assert.equal(resolveColorSupport({}, ttyOutput), false);
      delete process.env.NODE_DISABLE_COLORS;

      // FORCE_COLOR forces colors
      try {
        process.env.FORCE_COLOR = '1';
        assert.equal(resolveColorSupport({}, nonTtyOutput), true);
      } finally {
        delete process.env.FORCE_COLOR;
      }

      // Default behavior: TTY is true, non-TTY is false
      assert.equal(resolveColorSupport({}, ttyOutput), true);
      assert.equal(resolveColorSupport({}, nonTtyOutput), false);
    });
  });

  describe('Log Event Formatting & Graceful Degradation', () => {
    test('handles empty or missing event fields gracefully with sensible fallbacks', () => {
      const line = formatLogEvent({});
      assert.ok(line.includes('UNKNOWN-TIME'));
      assert.ok(line.includes('[INFO]'));
      assert.ok(line.includes('GET'));
      assert.ok(line.includes('/'));
      assert.ok(line.includes('unknown'));
      assert.ok(line.includes('No details'));
    });

    test('renders appropriate text badge for each action', () => {
      assert.ok(formatLogEvent({ action: 'blocked' }).includes('[BLOCKED]'));
      assert.ok(formatLogEvent({ action: 'warn' }).includes('[WARNED]'));
      assert.ok(formatLogEvent({ action: 'allowed' }).includes('[ALLOWED]'));
      assert.ok(formatLogEvent({ action: 'custom' }).includes('[CUSTOM]'));
    });

    test('strips hostile ANSI escapes from data even when color formatting is enabled', () => {
      const hostileEvent = {
        timestamp: '2026-10-19T12:00:00.000Z',
        action: 'blocked',
        ip: '198.51.100.99\x1b[2J\x1b[H',
        method: 'POST',
        route: '/admin\x1b[31;1mINJECTED',
        reason: 'Malicious\x1b[0m payload'
      };

      const line = formatLogEvent(hostileEvent, { colors: true });
      // Injected screen clear must not be present
      assert.equal(line.includes('\x1b[2J'), false);
      assert.equal(line.includes('\x1b[H'), false);
      assert.equal(line.includes('INJECTED'), true);
      // Controlled Z-Shield badge and color formatting is present
      assert.ok(line.includes('[BLOCKED]'));
      assert.ok(line.includes('\x1b[31m'));
    });

    test('produces zero ANSI escapes when colors: false', () => {
      const event = {
        timestamp: '2026-10-19T12:00:00.000Z',
        action: 'blocked',
        ip: '198.51.100.99',
        method: 'POST',
        route: '/admin/login',
        reason: 'Rate limit exceeded'
      };

      const line = formatLogEvent(event, { colors: false });
      assert.equal(line.includes('\x1b['), false);
      assert.ok(line.includes('[BLOCKED]'));
      assert.ok(line.includes('/admin/login'));
    });
  });

  describe('Colored vs Plain Output Modes in CLI Commands', () => {
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

    test('status command with --color outputs colored sections and badges', async () => {
      const logFile = path.join(tempDir, 'events.jsonl');
      fs.writeFileSync(
        logFile,
        JSON.stringify({
          timestamp: '2026-10-19T12:00:00.000Z',
          ip: '203.0.113.10',
          type: 'rate_limit',
          action: 'blocked',
          route: '/api/v1/checkout'
        }) + '\n'
      );

      const mock = createMockOutput();
      const code = await runCommand(['status', '--color', '--log-dir', tempDir], mock);
      assert.equal(code, 0);

      const out = mock.getStdout();
      // Should have ANSI codes
      assert.ok(out.includes('\x1b['));
      // Should have formatted sections and badges
      assert.ok(out.includes('Z-Shield Security Status'));
      assert.ok(out.includes('BLOCKED'));
      assert.ok(out.includes('Process-Local Architecture Notice'));
    });

    test('status command with --no-color outputs zero ANSI codes while preserving badges', async () => {
      const logFile = path.join(tempDir, 'events.jsonl');
      fs.writeFileSync(
        logFile,
        JSON.stringify({
          timestamp: '2026-10-19T12:00:00.000Z',
          ip: '203.0.113.10',
          type: 'rate_limit',
          action: 'blocked',
          route: '/api/v1/checkout'
        }) + '\n'
      );

      const mock = createMockOutput();
      const code = await runCommand(['status', '--no-color', '--log-dir', tempDir], mock);
      assert.equal(code, 0);

      const out = mock.getStdout();
      // Must not contain any ANSI escapes
      assert.equal(out.includes('\x1b['), false);
      // Badges and text headers must still be readable
      assert.ok(out.includes('Z-Shield Security Status'));
      assert.ok(out.includes('BLOCKED'));
      assert.ok(out.includes('Process-Local Architecture Notice'));
    });

    test('logs command outputs ANSI codes with --color and none with --no-color', async () => {
      const logFile = path.join(tempDir, 'events.jsonl');
      fs.writeFileSync(
        logFile,
        JSON.stringify({
          timestamp: '2026-10-19T12:00:00.000Z',
          ip: '203.0.113.10',
          type: 'rate_limit',
          action: 'blocked',
          route: '/api/v1/checkout',
          reason: 'Excessive requests'
        }) + '\n'
      );

      const colorMock = createMockOutput();
      await runCommand(['logs', '--color', '--log-dir', tempDir], colorMock);
      assert.ok(colorMock.getStdout().includes('\x1b['));
      assert.ok(colorMock.getStdout().includes('[BLOCKED]'));

      const plainMock = createMockOutput();
      await runCommand(['logs', '--no-color', '--log-dir', tempDir], plainMock);
      assert.equal(plainMock.getStdout().includes('\x1b['), false);
      assert.ok(plainMock.getStdout().includes('[BLOCKED]'));
    });

    test('command errors include [ERROR] prefix and respect --color / --no-color', async () => {
      const colorMock = createMockOutput();
      await runCommand(['block', 'not-an-ip', '--color'], colorMock);
      assert.ok(colorMock.getStderr().includes('[ERROR]'));
      assert.ok(colorMock.getStderr().includes('\x1b[31m')); // Red error

      const plainMock = createMockOutput();
      await runCommand(['block', 'not-an-ip', '--no-color'], plainMock);
      assert.ok(plainMock.getStderr().includes('[ERROR]'));
      assert.equal(plainMock.getStderr().includes('\x1b['), false); // No ANSI
    });
  });

  describe('Child Process Binary Invocation', () => {
    test('executes CLI binary directly using node', () => {
      const cliPath = path.resolve(__dirname, '../dist/cli.js');
      const output = execFileSync(process.execPath, [cliPath, '--help'], { encoding: 'utf8' });
      assert.ok(output.includes('Z-Shield CLI'));
      assert.ok(output.includes('npx z-shield status'));
      assert.ok(output.includes('npx z-shield monitor'));
    });
  });
});
