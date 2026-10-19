#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const readline = require('node:readline');

const { stripAnsi, sanitizeString } = require('./logger');
const { parseDuration, isValidIp } = require('./block-manager');

/**
 * Parses raw command-line arguments into a structured command object.
 *
 * @param {string[]} argv - Array of CLI arguments (typically process.argv.slice(2))
 * @returns {{ command: string, args: string[], options: Record<string, string|boolean> }}
 */
function parseCliArgs(argv = []) {
  let command = 'help';
  const args = [];
  const options = {};

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
 * @param {Record<string, any>} options
 * @returns {string} Absolute path to events.jsonl
 */
function resolveLogPath(options = {}) {
  const logDir = options['log-dir'] || options.logDir || path.join(process.cwd(), '.z-shield-logs');
  const filename = options['log-file'] || options.logFile || 'events.jsonl';
  return path.join(path.resolve(logDir), filename);
}

/**
 * Formats a single security event record into a clean, sanitized terminal line.
 * Strips all ANSI escapes and control characters from untrusted log fields.
 *
 * @param {Object} event
 * @returns {string} Sanitized output line
 */
function formatLogEvent(event) {
  if (!event || typeof event !== 'object') {
    return '[Malformed Event]';
  }

  const timestamp = sanitizeString(event.timestamp || 'UNKNOWN-TIME', 30);
  const severity = sanitizeString((event.severity || 'INFO').toUpperCase(), 10);
  const type = sanitizeString(event.type || 'unknown', 20);
  const action = sanitizeString((event.action || 'unknown').toUpperCase(), 10);
  const ip = sanitizeString(event.ip || 'unknown', 45);
  const method = sanitizeString((event.method || 'GET').toUpperCase(), 10);
  const route = sanitizeString(event.route || '/', 100);
  const reason = sanitizeString(event.reason || 'No details', 150);

  return `[${timestamp}] [${severity}] [${action}] ${method} ${route} | IP: ${ip} | ${type}: ${reason}`;
}

/**
 * Reads and parses the last N records from the JSON Lines file.
 * Handles missing files and skips malformed records gracefully.
 *
 * @param {string} logFilePath
 * @param {number} [limit=20]
 * @returns {{ events: Object[], totalLines: number, malformedCount: number, fileExists: boolean }}
 */
function readLogs(logFilePath, limit = 20) {
  if (!fs.existsSync(logFilePath)) {
    return { events: [], totalLines: 0, malformedCount: 0, fileExists: false };
  }

  const rawContent = fs.readFileSync(logFilePath, 'utf8');
  const rawLines = rawContent.split('\n').filter(line => line.trim().length > 0);

  let malformedCount = 0;
  const parsedEvents = [];

  for (const line of rawLines) {
    try {
      const parsed = JSON.parse(line);
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
 * Computes security summary statistics from the log file.
 *
 * @param {string} logFilePath
 * @returns {Object}
 */
function calculateStatus(logFilePath) {
  if (!fs.existsSync(logFilePath)) {
    return { fileExists: false, totalEvents: 0 };
  }

  const { events: allEvents, malformedCount } = readLogs(logFilePath, 100000);

  const ipCounts = {};
  const routeCounts = {};
  const typeCounts = {};
  const actionCounts = {};

  for (const event of allEvents) {
    const ip = event.ip || 'unknown';
    const route = event.route || '/';
    const type = event.type || 'unknown';
    const action = event.action || 'unknown';

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
 * @param {string[]} argv
 * @param {Console|Object} [output=console]
 * @returns {Promise<number>} Exit code
 */
async function runCommand(argv = process.argv.slice(2), output = console) {
  const { command, args, options } = parseCliArgs(argv);
  const logFilePath = resolveLogPath(options);

  switch (command) {
    case 'status': {
      output.log('====================================================');
      output.log('🛡️  Z-Shield Security Status');
      output.log('====================================================');
      output.log(`Log File: ${logFilePath}`);

      const status = calculateStatus(logFilePath);

      if (!status.fileExists) {
        output.log('Status:   No log file found yet.');
        output.log('ℹ Start your Express server to begin logging security events.');
        output.log('====================================================');
        return 0;
      }

      output.log(`Total Events Recorded: ${status.totalEvents}`);
      if (status.malformedCount > 0) {
        output.log(`Malformed Lines Skipped: ${status.malformedCount}`);
      }

      output.log('\nActions Breakdown:');
      for (const [action, count] of Object.entries(status.actionCounts)) {
        output.log(`  - ${action.toUpperCase()}: ${count}`);
      }

      output.log('\nEvent Types:');
      for (const [type, count] of Object.entries(status.typeCounts)) {
        output.log(`  - ${type}: ${count}`);
      }

      if (status.topIps.length > 0) {
        output.log('\nTop Offending IPs:');
        for (const item of status.topIps) {
          output.log(`  - ${item.ip}: ${item.count} events`);
        }
      }

      if (status.topRoutes.length > 0) {
        output.log('\nTop Targeted Routes:');
        for (const item of status.topRoutes) {
          output.log(`  - ${item.route}: ${item.count} events`);
        }
      }

      output.log('====================================================');
      return 0;
    }

    case 'logs': {
      let limit = 20;
      if (options.limit) {
        const parsed = parseInt(options.limit, 10);
        if (isNaN(parsed) || parsed <= 0) {
          output.error('❌ Error: --limit must be a positive integer.');
          return 1;
        }
        limit = parsed;
      }

      const { events, totalLines, malformedCount, fileExists } = readLogs(logFilePath, limit);

      output.log('====================================================');
      output.log(`🛡️  Z-Shield Security Logs (Showing last ${events.length} of ${totalLines} events)`);
      output.log(`Source: ${logFilePath}`);
      output.log('====================================================');

      if (!fileExists || events.length === 0) {
        output.log('ℹ No security events found in log file.');
        output.log('====================================================');
        return 0;
      }

      for (const event of events) {
        output.log(formatLogEvent(event));
      }

      if (malformedCount > 0) {
        output.log(`\n⚠️  Notice: Skipped ${malformedCount} unparseable or corrupted lines.`);
      }

      output.log('====================================================');
      return 0;
    }

    case 'monitor': {
      output.log('====================================================');
      output.log('🛡️  Z-Shield Live Security Event Monitor');
      output.log(`Watching: ${logFilePath}`);
      output.log('Press Ctrl+C to exit.');
      output.log('====================================================');

      let currentSize = 0;
      if (fs.existsSync(logFilePath)) {
        currentSize = fs.statSync(logFilePath).size;
        // Show recent events for immediate context
        const { events } = readLogs(logFilePath, 5);
        if (events.length > 0) {
          output.log('--- Recent Events ---');
          for (const ev of events) {
            output.log(formatLogEvent(ev));
          }
          output.log('--- Live Stream Active ---');
        }
      } else {
        output.log('ℹ Waiting for server to create log file...');
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
              buffer = lines.pop(); // keep last partial line
              for (const line of lines) {
                if (line.trim().length > 0) {
                  try {
                    const parsed = JSON.parse(line);
                    output.log(formatLogEvent(parsed));
                  } catch {
                    output.log('[⚠️ Corrupted log record]');
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
      return new Promise((resolve) => {
        const cleanup = () => {
          clearInterval(interval);
          output.log('\n👋 Exiting Z-Shield live monitor.');
          resolve(0);
        };

        process.once('SIGINT', cleanup);
        process.once('SIGTERM', cleanup);
      });
    }

    case 'block': {
      const ip = args[0];
      if (!ip) {
        output.error('❌ Error: Missing IP address. Usage: npx z-shield block <ip> [--duration 10m] [--reason <text>]');
        return 1;
      }

      if (!isValidIp(ip)) {
        output.error(`❌ Error: Invalid IP address "${ip}". Must be a valid IPv4 or IPv6 address.`);
        return 1;
      }

      const durationRaw = options.duration || '15m';
      let durationMs;
      try {
        durationMs = parseDuration(durationRaw);
      } catch (err) {
        output.error(`❌ Error: ${err.message}`);
        return 1;
      }

      const reason = options.reason || 'Manual block requested via CLI';

      output.log('====================================================');
      output.log('🛡️  Z-Shield CLI: Block Request');
      output.log('====================================================');
      output.log(`Target IP:  ${ip}`);
      output.log(`Duration:   ${durationRaw} (${durationMs.toLocaleString()}ms)`);
      output.log(`Reason:     ${reason}`);
      output.log('\nℹ Process-Local Architecture Notice:');
      output.log('Z-Shield manages active temporary blocks in server memory (RAM).');
      output.log('Because this CLI runs in an independent Node.js process, it cannot');
      output.log('directly modify the running Express server\'s memory heap without an');
      output.log('external IPC socket or database (which Z-Shield intentionally avoids).');
      output.log('\nTo block this IP in your running Express application:');
      output.log(`  shield.block('${ip}', '${durationRaw}', '${reason}');`);

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
        output.log(`\nAudit entry recorded in: ${logFilePath}`);
      } catch {
        // Safe fallback
      }

      output.log('====================================================');
      return 0;
    }

    case 'unblock': {
      const ip = args[0];
      if (!ip) {
        output.error('❌ Error: Missing IP address. Usage: npx z-shield unblock <ip>');
        return 1;
      }

      if (!isValidIp(ip)) {
        output.error(`❌ Error: Invalid IP address "${ip}". Must be a valid IPv4 or IPv6 address.`);
        return 1;
      }

      output.log('====================================================');
      output.log('🛡️  Z-Shield CLI: Unblock Request');
      output.log('====================================================');
      output.log(`Target IP:  ${ip}`);
      output.log('\nℹ Process-Local Architecture Notice:');
      output.log('Z-Shield manages active temporary blocks in server memory (RAM).');
      output.log('\nTo unblock this IP in your running Express application:');
      output.log(`  shield.unblock('${ip}');`);

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
        output.log(`\nAudit entry recorded in: ${logFilePath}`);
      } catch {
        // Safe fallback
      }

      output.log('====================================================');
      return 0;
    }

    case 'help':
    default: {
      output.log('====================================================');
      output.log('🛡️  Z-Shield CLI — API Abuse Detection & Protection');
      output.log('====================================================');
      output.log('Usage:');
      output.log('  npx z-shield status                Show security overview and top offender IPs');
      output.log('  npx z-shield logs [--limit 50]     Display recent security event logs');
      output.log('  npx z-shield monitor               Stream security events in real time');
      output.log('  npx z-shield block <ip>            Instructions & audit for blocking an IP');
      output.log('  npx z-shield unblock <ip>          Instructions & audit for unblocking an IP');
      output.log('\nOptions:');
      output.log('  --limit <number>                   Number of log entries to display (default: 20)');
      output.log('  --duration <time>                  Block duration (e.g. 10m, 1h, 30s)');
      output.log('  --log-dir <path>                   Path to log directory (default: .z-shield-logs)');
      output.log('  --help, -h                         Display this help message');
      output.log('====================================================');
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

module.exports = {
  parseCliArgs,
  formatLogEvent,
  readLogs,
  calculateStatus,
  resolveLogPath,
  runCommand
};
