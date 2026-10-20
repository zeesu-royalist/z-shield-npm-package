#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { stripAnsi, sanitizeString, sanitizeRoute } from './logger';
import { parseDuration, isValidIp, normalizeIp } from './block-manager';

export interface ParsedCliArgs {
  command: string;
  args: string[];
  options: Record<string, string | boolean>;
}

export type ColorFormatter = (str: string | number | undefined | null) => string;

export interface ColorMap {
  bold: ColorFormatter;
  dim: ColorFormatter;
  italic: ColorFormatter;
  underline: ColorFormatter;
  inverse: ColorFormatter;
  red: ColorFormatter;
  green: ColorFormatter;
  yellow: ColorFormatter;
  blue: ColorFormatter;
  magenta: ColorFormatter;
  cyan: ColorFormatter;
  white: ColorFormatter;
  gray: ColorFormatter;
  enabled: boolean;
  hasColors: boolean;
}

export interface CliOutput {
  log: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
  isTTY?: boolean;
}

export interface LogReadResult {
  events: Record<string, unknown>[];
  totalLines: number;
  malformedCount: number;
  fileExists: boolean;
}

export interface StatusResult {
  fileExists: boolean;
  totalEvents: number;
  malformedCount?: number;
  typeCounts?: Record<string, number>;
  actionCounts?: Record<string, number>;
  topIps?: Array<{ ip: string; count: number }>;
  topRoutes?: Array<{ route: string; count: number }>;
}

/**
 * Parses raw command-line arguments into a structured command object.
 *
 * @param argv - Array of CLI arguments (typically process.argv.slice(2))
 * @returns Structured CLI command, positional args, and parsed options
 */
export function parseCliArgs(argv: string[] = []): ParsedCliArgs {
  let command = 'help';
  const args: string[] = [];
  const options: Record<string, string | boolean> = {};

  let i = 0;
  // If first non-flag argument exists, it's the command
  while (i < argv.length) {
    const token = argv[i];
    if (token.startsWith('--') || token.startsWith('-')) {
      const cleanKey = token.replace(/^-+/, '');
      // Check if next token is value
      if (i + 1 < argv.length && !argv[i + 1].startsWith('-')) {
        options[cleanKey] = argv[i + 1];
        i += 2;
      } else {
        options[cleanKey] = true;
        i += 1;
      }
    } else {
      if (command === 'help') {
        command = token.toLowerCase();
      } else {
        args.push(token);
      }
      i += 1;
    }
  }

  if (options.help || options.h) {
    command = 'help';
  }

  return { command, args, options };
}

/**
 * Resolves the target JSON Lines log file path based on CLI options or defaults.
 *
 * @param options - Parsed CLI options
 * @returns Absolute path to events.jsonl
 */
export function resolveLogPath(options: Record<string, unknown> = {}): string {
  const logDirOption = (options['log-dir'] || options.logDir) as string | undefined;
  const envLogDir = process.env.Z_SHIELD_LOG_DIR;
  const filenameOption = (options['log-file'] || options.logFile) as string | undefined;

  // Precedence:
  // 1. Explicit CLI option: --log-dir / --logDir
  // 2. Environment variable: Z_SHIELD_LOG_DIR (if non-empty)
  // 3. Default: .z-shield-logs in current working directory
  let targetDir: string;
  if (typeof logDirOption === 'string' && logDirOption.trim().length > 0) {
    targetDir = logDirOption.trim();
  } else if (typeof envLogDir === 'string' && envLogDir.trim().length > 0) {
    targetDir = envLogDir.trim();
  } else {
    targetDir = path.join(process.cwd(), '.z-shield-logs');
  }

  const logDir = path.resolve(targetDir);
  const filename = typeof filenameOption === 'string' && filenameOption.trim().length > 0
    ? filenameOption.trim()
    : 'events.jsonl';

  return path.join(logDir, filename);
}

/**
 * Creates an ANSI color styling helper object.
 * When enabled is false, all styling methods act as plain passthroughs.
 *
 * @param enabled - Whether color styling is active
 * @returns Color styling map
 */
export function createColors(enabled: boolean = true): ColorMap {
  if (!enabled) {
    const pass: ColorFormatter = (str) => String(str ?? '');
    return {
      bold: pass,
      dim: pass,
      italic: pass,
      underline: pass,
      inverse: pass,
      red: pass,
      green: pass,
      yellow: pass,
      blue: pass,
      magenta: pass,
      cyan: pass,
      white: pass,
      gray: pass,
      enabled: false,
      hasColors: false
    };
  }

  const wrap = (open: number, close: number): ColorFormatter =>
    (str) => `\x1b[${open}m${str ?? ''}\x1b[${close}m`;

  return {
    bold: wrap(1, 22),
    dim: wrap(2, 22),
    italic: wrap(3, 23),
    underline: wrap(4, 24),
    inverse: wrap(7, 27),
    red: wrap(31, 39),
    green: wrap(32, 39),
    yellow: wrap(33, 39),
    blue: wrap(34, 39),
    magenta: wrap(35, 39),
    cyan: wrap(36, 39),
    white: wrap(37, 39),
    gray: wrap(90, 39),
    enabled: true,
    hasColors: true
  };
}

/**
 * Determines whether terminal colors should be enabled based on
 * explicit options, environment variables, and TTY capabilities.
 *
 * Respects the standard NO_COLOR specification (https://no-color.org).
 *
 * @param options - Parsed CLI options
 * @param output - Output destination (console or mock stream)
 * @returns True if colors should be enabled
 */
export function resolveColorSupport(
  options: Record<string, unknown> = {},
  output: CliOutput | Console | null = null
): boolean {
  // 1. Explicit CLI flags
  if (
    options['no-color'] ||
    options.noColor ||
    options.color === false ||
    options.colors === false ||
    options.color === 'false' ||
    options.colors === 'false'
  ) {
    return false;
  }
  if (
    options.color === true ||
    options.colors === true ||
    options.color === 'true' ||
    options.colors === 'true' ||
    options.color === ''
  ) {
    return true;
  }

  // 2. NO_COLOR standard (https://no-color.org)
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') {
    return false;
  }

  // 3. Node.js NODE_DISABLE_COLORS
  if (process.env.NODE_DISABLE_COLORS === '1') {
    return false;
  }

  // 4. FORCE_COLOR override
  if (process.env.FORCE_COLOR !== undefined) {
    return process.env.FORCE_COLOR !== '0';
  }

  // 5. If output is a custom test mock or stream without TTY, disable colors by default
  if (output && output !== console) {
    return Boolean((output as CliOutput).isTTY);
  }

  // 6. Interactive terminal check
  return Boolean(process.stdout && process.stdout.isTTY);
}

/**
 * Formats a single security event record into a clean, sanitized terminal line.
 * Strips all ANSI escapes and control characters from untrusted log fields before formatting.
 *
 * @param event - Security event object
 * @param options - Options object or boolean for color
 * @returns Sanitized output line
 */
export function formatLogEvent(
  event: Record<string, unknown> | null | undefined,
  options: Record<string, unknown> | boolean = {}
): string {
  if (!event || typeof event !== 'object') {
    return '[Malformed Event]';
  }

  let useColors = false;
  if (typeof options === 'boolean') {
    useColors = options;
  } else if (options && typeof options === 'object') {
    if (typeof options.colors === 'boolean') {
      useColors = options.colors;
    } else if (typeof options.color === 'boolean') {
      useColors = options.color;
    } else if (options.colors === 'true' || options.color === 'true') {
      useColors = true;
    } else if (options.colors === 'false' || options.color === 'false' || options['no-color']) {
      useColors = false;
    }
  }
  const c = createColors(useColors);

  // Sanitize untrusted log values first to prevent terminal injection
  const timestamp = sanitizeString(event.timestamp || 'UNKNOWN-TIME', 30);
  const severity = sanitizeString((event.severity || 'INFO'), 10).toUpperCase();
  const type = sanitizeString(event.type || 'unknown', 20);
  const rawAction = String(event.action || 'unknown').toUpperCase();
  const normalizedAction = rawAction === 'WARN' ? 'WARNED'
    : rawAction === 'BLOCK' ? 'BLOCKED'
    : rawAction === 'ALLOW' ? 'ALLOWED'
    : rawAction;
  const action = sanitizeString(normalizedAction, 10);
  const ip = sanitizeString(event.ip || 'unknown', 45);
  const method = sanitizeString(event.method || 'GET', 10).toUpperCase();
  const route = sanitizeString(event.route || '/', 100);
  const reason = sanitizeString(event.reason || 'No details', 150);

  if (!useColors) {
    return `[${timestamp}] [${severity}] [${action}] ${method} ${route} | IP: ${ip} | ${type}: ${reason}`;
  }

  // Action badge with semantic color
  let styledAction: string;
  switch (action) {
    case 'BLOCKED': styledAction = c.bold(c.red(`[${action}]`)); break;
    case 'WARNED': styledAction = c.bold(c.yellow(`[${action}]`)); break;
    case 'ALLOWED': styledAction = c.bold(c.green(`[${action}]`)); break;
    case 'UNBLOCKED': styledAction = c.bold(c.cyan(`[${action}]`)); break;
    case 'REQUESTED': styledAction = c.bold(c.blue(`[${action}]`)); break;
    default: styledAction = c.bold(`[${action}]`); break;
  }

  // Severity badge with semantic color
  let styledSeverity: string;
  switch (severity) {
    case 'CRITICAL': styledSeverity = c.bold(c.red(`[${severity}]`)); break;
    case 'WARNING': styledSeverity = c.bold(c.yellow(`[${severity}]`)); break;
    case 'INFO': styledSeverity = c.bold(c.green(`[${severity}]`)); break;
    default: styledSeverity = c.bold(`[${severity}]`); break;
  }

  const styledTimestamp = c.gray(`[${timestamp}]`);
  const styledMethod = c.bold(method);
  const styledRoute = c.cyan(route);
  const styledIp = c.bold(ip);
  const styledType = c.yellow(type);

  return `${styledTimestamp} ${styledSeverity} ${styledAction} ${styledMethod} ${styledRoute} | IP: ${styledIp} | ${styledType}: ${reason}`;
}

/**
 * Reads and parses the last N records from the JSON Lines file.
 * Handles missing files and skips malformed records gracefully.
 *
 * @param logFilePath - Path to log file
 * @param limit - Max number of events to return
 * @returns Extracted events and counts
 */
export function readLogs(logFilePath: string, limit: number = 20): LogReadResult {
  if (!fs.existsSync(logFilePath)) {
    return { events: [], totalLines: 0, malformedCount: 0, fileExists: false };
  }

  const rawContent = fs.readFileSync(logFilePath, 'utf8');
  const rawLines = rawContent.split('\n').filter(line => line.trim().length > 0);

  let malformedCount = 0;
  const parsedEvents: Record<string, unknown>[] = [];

  for (const line of rawLines) {
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      parsedEvents.push(parsed);
    } catch {
      malformedCount++;
    }
  }

  const selected = parsedEvents.slice(-limit);

  return {
    events: selected,
    totalLines: rawLines.length,
    malformedCount,
    fileExists: true
  };
}

/**
 * Sanitizes untrusted IP address values from logs for safe status aggregation and output.
 * Strips ANSI escapes, truncates at newlines/control characters, and extracts valid IP addresses.
 *
 * @param rawIp - Untrusted IP candidate from logs
 * @returns Normalized IP address or 'unknown'
 */
export function sanitizeIp(rawIp: unknown): string {
  if (!rawIp || typeof rawIp !== 'string') return 'unknown';
  const trimmed = rawIp.trim();
  if (trimmed.length === 0) return 'unknown';

  if (net.isIP(trimmed) !== 0) {
    return normalizeIp(trimmed);
  }

  const stripped = stripAnsi(trimmed);
  if (net.isIP(stripped) !== 0) {
    return normalizeIp(stripped);
  }

  const beforeEscape = trimmed.split(/[\x1b\r\n\x00-\x1f\x7f]/)[0].trim();
  if (beforeEscape.length > 0 && net.isIP(beforeEscape) !== 0) {
    return normalizeIp(beforeEscape);
  }

  const ipv4Match = stripped.match(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/);
  if (ipv4Match && net.isIP(ipv4Match[0]) === 4) {
    return normalizeIp(ipv4Match[0]);
  }

  const ipv6Candidates = stripped.match(/[0-9a-fA-F:]+/g);
  if (ipv6Candidates) {
    for (const cand of ipv6Candidates) {
      if (net.isIP(cand) === 6) {
        return normalizeIp(cand);
      }
    }
  }

  return 'unknown';
}

/**
 * Sanitizes untrusted event type strings from logs.
 *
 * @param rawType - Untrusted event type string
 * @param maxLength - Maximum permitted length
 * @returns Clean event type string
 */
export function sanitizeType(rawType: unknown, maxLength: number = 30): string {
  if (!rawType || typeof rawType !== 'string') return 'unknown';
  let clean = rawType.split(/[\r\n\x1b]/)[0];
  clean = stripAnsi(clean);
  clean = clean.replace(/[\x00-\x1f\x7f]/g, ' ').trim();
  clean = clean.replace(/\s+/g, ' ');
  return clean.slice(0, maxLength) || 'unknown';
}

/**
 * Sanitizes untrusted action strings from logs.
 *
 * @param rawAction - Untrusted action string
 * @param maxLength - Maximum permitted length
 * @returns Clean action string
 */
export function sanitizeAction(rawAction: unknown, maxLength: number = 20): string {
  if (!rawAction || typeof rawAction !== 'string') return 'unknown';
  let clean = rawAction.split(/[\r\n\x1b]/)[0];
  clean = stripAnsi(clean);
  clean = clean.replace(/[\x00-\x1f\x7f]/g, '').trim().toLowerCase();
  if (clean === 'warn') clean = 'warned';
  else if (clean === 'block') clean = 'blocked';
  else if (clean === 'allow') clean = 'allowed';
  return clean.slice(0, maxLength) || 'unknown';
}

/**
 * Computes security summary statistics from the log file.
 *
 * @param logFilePath - Path to log file
 * @returns Summary metrics
 */
export function calculateStatus(logFilePath: string): StatusResult {
  if (!fs.existsSync(logFilePath)) {
    return { fileExists: false, totalEvents: 0 };
  }

  const { events: allEvents, malformedCount } = readLogs(logFilePath, 100000);

  const ipCounts = Object.create(null) as Record<string, number>;
  const routeCounts = Object.create(null) as Record<string, number>;
  const typeCounts = Object.create(null) as Record<string, number>;
  const actionCounts = Object.create(null) as Record<string, number>;

  for (const event of allEvents) {
    const ip = sanitizeIp(event.ip);
    const route = sanitizeRoute(event.route);
    const type = sanitizeType(event.type);
    const action = sanitizeAction(event.action);

    ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    routeCounts[route] = (routeCounts[route] || 0) + 1;
    typeCounts[type] = (typeCounts[type] || 0) + 1;
    actionCounts[action] = (actionCounts[action] || 0) + 1;
  }

  // Sort top offenders
  const topIps = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, count]) => ({ ip, count }));

  const topRoutes = Object.entries(routeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([route, count]) => ({ route, count }));

  return {
    fileExists: true,
    totalEvents: allEvents.length,
    malformedCount,
    typeCounts,
    actionCounts,
    topIps,
    topRoutes
  };
}

/**
 * Main command runner. Returns an exit code (0 for success, 1 for error).
 *
 * @param argv - Arguments array
 * @param output - Output destination (console or mock object)
 * @returns Exit code
 */
export async function runCommand(
  argv: string[] = process.argv.slice(2),
  output: CliOutput | Console = console
): Promise<number> {
  const { command, args, options } = parseCliArgs(argv);
  const logFilePath = resolveLogPath(options);
  const useColors = resolveColorSupport(options, output);
  const c = createColors(useColors);

  switch (command) {
    case 'status': {
      output.log(c.cyan('\n\n===================================================='));
      output.log(c.bold(c.cyan('🛡️  Z-Shield Security Status')));
      output.log(c.cyan('===================================================='));
      output.log(`${c.bold('Log File:')} ${c.gray(logFilePath)}`);

      const status = calculateStatus(logFilePath);

      if (!status.fileExists) {
        output.log(`${c.bold('Status:')}   ${c.yellow('No log file found yet.')}`);
        output.log(`\n${c.bold('Checked Location:')} ${c.gray(logFilePath)}`);
        output.log(c.dim('ℹ Start your Express or Next.js server to begin logging security events.'));
        output.log(c.dim('  If your application stores logs in a custom directory, specify it with:'));
        output.log(c.dim('    • CLI flag:             z-shield status --log-dir <path>'));
        output.log(c.dim('    • Environment variable: Z_SHIELD_LOG_DIR=<path> z-shield status'));
        output.log(c.cyan('====================================================\n'));
        return 0;
      }

      output.log(`${c.bold('Total Events Recorded:')} ${c.bold(c.cyan(status.totalEvents))}`);
      if (status.malformedCount && status.malformedCount > 0) {
        output.log(`${c.bold(c.yellow('⚠️  Malformed Lines Skipped:'))} ${c.yellow(status.malformedCount)}`);
      }

      output.log(`\n${c.bold('Actions Breakdown:')}`);
      if (status.actionCounts) {
        for (const [action, count] of Object.entries(status.actionCounts)) {
          const cleanAction = sanitizeAction(action);
          const upper = cleanAction.toUpperCase();
          let styledAction = upper;
          if (upper === 'BLOCKED') styledAction = c.bold(c.red(upper));
          else if (upper === 'WARNED') styledAction = c.bold(c.yellow(upper));
          else if (upper === 'ALLOWED') styledAction = c.bold(c.green(upper));
          else if (upper === 'UNBLOCKED') styledAction = c.bold(c.cyan(upper));
          else if (upper === 'REQUESTED') styledAction = c.bold(c.blue(upper));
          output.log(`  - ${styledAction}: ${c.bold(count)}`);
        }
      }

      output.log(`\n${c.bold('Event Types:')}`);
      if (status.typeCounts) {
        for (const [type, count] of Object.entries(status.typeCounts)) {
          const cleanType = sanitizeType(type);
          output.log(`  - ${c.yellow(cleanType)}: ${c.bold(count)}`);
        }
      }

      if (status.topIps && status.topIps.length > 0) {
        output.log(`\n${c.bold('Top Offending IPs:')}`);
        for (const item of status.topIps) {
          const cleanIp = sanitizeIp(item.ip);
          output.log(`  - ${c.cyan(cleanIp)}: ${c.bold(item.count)} events`);
        }
      }

      if (status.topRoutes && status.topRoutes.length > 0) {
        output.log(`\n${c.bold('Top Targeted Routes:')}`);
        for (const item of status.topRoutes) {
          const cleanRoute = sanitizeRoute(item.route);
          output.log(`  - ${c.underline(cleanRoute)}: ${c.bold(item.count)} events`);
        }
      }

      output.log(`\n${c.dim('ℹ Process-Local Architecture Notice:')}`);
      output.log(c.dim('Statistics reflect historical events recorded in the local log file.'));
      output.log(c.dim('Active in-memory counters and temporary blocks reside in server RAM'));
      output.log(c.dim('and are managed inside the running Express process.'));

      output.log(c.cyan('===================================================='));
      return 0;
    }

    case 'logs': {
      let limit = 20;
      if (options.limit) {
        const parsed = parseInt(String(options.limit), 10);
        if (isNaN(parsed) || parsed <= 0) {
          output.error(c.bold(c.red('[ERROR] --limit must be a positive integer.')));
          return 1;
        }
        limit = parsed;
      }

      const { events, totalLines, malformedCount, fileExists } = readLogs(logFilePath, limit);

      output.log(c.cyan('\n\n===================================================='));
      output.log(c.bold(c.cyan(`🛡️  Z-Shield Security Logs (Showing last ${events.length} of ${totalLines} events)`)));
      output.log(`${c.bold('Source:')} ${c.gray(logFilePath)}`);
      output.log(c.cyan('===================================================='));

      if (!fileExists || events.length === 0) {
        if (!fileExists) {
          output.log(c.yellow(`ℹ No log file found at: ${logFilePath}`));
          output.log(c.dim('  Ensure your Express or Next.js server has started and recorded events.'));
          output.log(c.dim('  If your logs are stored in a custom directory, specify it with:'));
          output.log(c.dim('    • CLI flag:             z-shield logs --log-dir <path>'));
          output.log(c.dim('    • Environment variable: Z_SHIELD_LOG_DIR=<path> z-shield logs'));
        } else {
          output.log(c.dim('ℹ No security events found in log file.'));
        }
        output.log(c.cyan('===================================================='));
        return 0;
      }

      for (const event of events) {
        output.log(formatLogEvent(event, { colors: useColors }));
      }

      if (malformedCount > 0) {
        output.log(`\n${c.yellow(`⚠️  Notice: Skipped ${malformedCount} unparseable or corrupted lines.`)}`);
      }

      output.log(c.cyan('===================================================='));
      return 0;
    }

    case 'monitor': {
      output.log(c.cyan('\n\n===================================================='));
      output.log(c.bold(c.cyan('🛡️  Z-Shield Live Security Event Monitor')));
      output.log(`${c.bold('Watching:')} ${c.gray(logFilePath)}`);
      output.log(c.dim('Press Ctrl+C to exit.'));
      output.log(c.cyan('===================================================='));

      let currentSize = 0;
      if (fs.existsSync(logFilePath)) {
        currentSize = fs.statSync(logFilePath).size;
        // Show recent events for immediate context
        const { events } = readLogs(logFilePath, 5);
        if (events.length > 0) {
          output.log(c.dim('--- Recent Events ---'));
          for (const ev of events) {
            output.log(formatLogEvent(ev, { colors: useColors }));
          }
          output.log(c.dim('--- Live Stream Active ---'));
        }
      } else {
        output.log(c.yellow(`ℹ Waiting for log file to be created at: ${logFilePath}`));
        output.log(c.dim('  Tip: You can specify a custom directory with --log-dir <path> or Z_SHIELD_LOG_DIR=<path>.'));
      }

      // Live watcher polling function
      const checkNewLines = () => {
        if (!fs.existsSync(logFilePath)) {
          return;
        }
        try {
          const stats = fs.statSync(logFilePath);
          if (stats.size > currentSize) {
            const stream = fs.createReadStream(logFilePath, {
              start: currentSize,
              end: stats.size,
              encoding: 'utf8'
            });

            currentSize = stats.size;

            let buffer = '';
            stream.on('data', chunk => {
              buffer += chunk;
              const lines = buffer.split('\n');
              buffer = lines.pop() || ''; // keep last partial line
              for (const line of lines) {
                if (line.trim().length > 0) {
                  try {
                    const parsed = JSON.parse(line) as Record<string, unknown>;
                    output.log(formatLogEvent(parsed, { colors: useColors }));
                  } catch {
                    output.log(c.yellow('[⚠️ Corrupted log record]'));
                  }
                }
              }
            });
          } else if (stats.size < currentSize) {
            // File was rotated or truncated!
            currentSize = 0;
          }
        } catch {
          // Non-fatal read error
        }
      };

      // Poll every 300ms for responsive terminal updates
      const interval = setInterval(checkNewLines, 300);

      // Clean exit on SIGINT (Ctrl+C)
      return new Promise<number>((resolve) => {
        const cleanup = () => {
          clearInterval(interval);
          output.log(`\n${c.cyan('👋 Exiting Z-Shield live monitor.')}`);
          resolve(0);
        };

        process.once('SIGINT', cleanup);
        process.once('SIGTERM', cleanup);
      });
    }

    case 'block': {
      const ip = args[0];
      if (!ip) {
        output.error(c.bold(c.red('[ERROR] Missing IP address. Usage: npx z-shield block <ip> [--duration 10m] [--reason <text>]')));
        return 1;
      }

      if (!isValidIp(ip)) {
        output.error(c.bold(c.red(`[ERROR] Invalid IP address "${ip}". Must be a valid IPv4 or IPv6 address.`)));
        return 1;
      }

      const durationRaw = (options.duration as string) || '15m';
      let durationMs: number;
      try {
        durationMs = parseDuration(durationRaw);
      } catch (err) {
        output.error(c.bold(c.red(`[ERROR] ${(err as Error).message}`)));
        return 1;
      }

      const reason = (options.reason as string) || 'Manual block requested via CLI';

      output.log(c.cyan('\n\n===================================================='));
      output.log(c.bold(c.cyan('🛡️  Z-Shield CLI: Block Request')));
      output.log(c.cyan('===================================================='));
      output.log(`${c.bold('Target IP:')}  ${c.bold(c.cyan(ip))}`);
      output.log(`${c.bold('Duration:')}   ${c.yellow(durationRaw)} (${durationMs.toLocaleString()}ms)`);
      output.log(`${c.bold('Reason:')}     ${reason}`);
      output.log(`\n${c.bold(c.yellow('ℹ Process-Local Architecture Notice:'))}`);
      output.log(c.dim('Z-Shield manages active temporary blocks in server memory (RAM).'));
      output.log(c.dim('Because this CLI runs in an independent Node.js process, it cannot'));
      output.log(c.dim("directly modify the running Express server's memory heap without an"));
      output.log(c.dim('external IPC socket or database (which Z-Shield intentionally avoids).'));
      output.log(`\n${c.bold('To block this IP in your running Express application:')}`);
      output.log(c.green(`  shield.block('${ip}', '${durationRaw}', '${reason}');`));

      // Record an audit log event
      try {
        fs.mkdirSync(path.dirname(logFilePath), { recursive: true });
        const auditEvent = {
          timestamp: new Date().toISOString(),
          appName: 'cli',
          type: 'cli_block_requested',
          severity: 'info',
          ip,
          method: 'CLI',
          route: '/cli/block',
          reason: `Requested duration: ${durationRaw} | Reason: ${reason}`,
          action: 'requested'
        };
        fs.appendFileSync(logFilePath, JSON.stringify(auditEvent) + '\n');
        output.log(`\n${c.green('✔')} Audit entry recorded in: ${c.gray(logFilePath)}`);
      } catch {
        // Safe fallback
      }

      output.log(c.cyan('===================================================='));
      return 0;
    }

    case 'unblock': {
      const ip = args[0];
      if (!ip) {
        output.error(c.bold(c.red('[ERROR] Missing IP address. Usage: npx z-shield unblock <ip>')));
        return 1;
      }

      if (!isValidIp(ip)) {
        output.error(c.bold(c.red(`[ERROR] Invalid IP address "${ip}". Must be a valid IPv4 or IPv6 address.`)));
        return 1;
      }

      output.log(c.cyan('\n\n===================================================='));
      output.log(c.bold(c.cyan('🛡️  Z-Shield CLI: Unblock Request')));
      output.log(c.cyan('===================================================='));
      output.log(`${c.bold('Target IP:')}  ${c.bold(c.cyan(ip))}`);
      output.log(`\n${c.bold(c.yellow('ℹ Process-Local Architecture Notice:'))}`);
      output.log(c.dim('Z-Shield manages active temporary blocks in server memory (RAM).'));
      output.log(`\n${c.bold('To unblock this IP in your running Express application:')}`);
      output.log(c.green(`  shield.unblock('${ip}');`));

      // Record an audit log event
      try {
        fs.mkdirSync(path.dirname(logFilePath), { recursive: true });
        const auditEvent = {
          timestamp: new Date().toISOString(),
          appName: 'cli',
          type: 'cli_unblock_requested',
          severity: 'info',
          ip,
          method: 'CLI',
          route: '/cli/unblock',
          reason: 'Manual unblock requested via CLI',
          action: 'requested'
        };
        fs.appendFileSync(logFilePath, JSON.stringify(auditEvent) + '\n');
        output.log(`\n${c.green('✔')} Audit entry recorded in: ${c.gray(logFilePath)}`);
      } catch {
        // Safe fallback
      }

      output.log(c.cyan('===================================================='));
      return 0;
    }

    case 'help':
    default: {
      output.log(c.cyan('\n\n===================================================='));
      output.log(c.bold(c.cyan('🛡️  Z-Shield CLI — API Abuse Detection & Protection')));
      output.log(c.cyan('===================================================='));
      output.log(c.bold('Usage:'));
      output.log(`  ${c.bold('npx z-shield')} ${c.cyan('<command>')} [options]`);
      output.log(`\n${c.bold('Commands:')}`);
      output.log(`  ${c.bold('npx z-shield status')}                Show security overview and top offender IPs`);
      output.log(`  ${c.bold('npx z-shield logs')} [--limit 50]     Display recent security event logs`);
      output.log(`  ${c.bold('npx z-shield monitor')}               Stream security events in real time`);
      output.log(`  ${c.bold('npx z-shield block')} <ip>            Instructions & audit for blocking an IP`);
      output.log(`  ${c.bold('npx z-shield unblock')} <ip>          Instructions & audit for unblocking an IP`);
      output.log(`\n${c.bold('Options:')}`);
      output.log(`  ${c.yellow('--limit')} <number>                   Number of log entries to display (default: 20)`);
      output.log(`  ${c.yellow('--duration')} <time>                  Block duration (e.g. 10m, 1h, 30s)`);
      output.log(`  ${c.yellow('--reason')} <text>                    Reason for manual block`);
      output.log(`  ${c.yellow('--log-dir')} <path>                   Path to log directory (default: .z-shield-logs)`);
      output.log(`  ${c.yellow('--color')}                            Force enable colored terminal output`);
      output.log(`  ${c.yellow('--no-color')}                         Disable colored terminal output`);
      output.log(`  ${c.yellow('--help, -h')}                         Display this help message`);
      output.log(`\n${c.bold('Environment Variables:')}`);
      output.log(`  ${c.yellow('Z_SHIELD_LOG_DIR')}                    Default log directory path when --log-dir is omitted`);
      output.log(c.cyan('===================================================='));
      return command === 'help' ? 0 : 1;
    }
  }
}

// Execute directly if run from CLI
if (require.main === module) {
  runCommand(process.argv.slice(2)).then(code => {
    if (code !== 0) {
      process.exit(code);
    }
  });
}
