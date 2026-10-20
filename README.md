# 🛡️ Z-Shield

> Lightweight, zero-dependency API abuse detection, rate limiting, and security event logging toolkit for Node.js and Express backends.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-0%20runtime-blue.svg)](package.json)

---

## Table of Contents

- [What is Z-Shield?](#what-is-z-shield)
  - [What Z-Shield Does](#what-z-shield-does)
  - [What Z-Shield Does NOT Do](#what-z-shield-does-not-do)
- [Requirements & Installation](#requirements--installation)
- [Quick Start: Express Integration](#quick-start-express-integration)
- [Quick Start: Next.js App Router Integration](#quick-start-nextjs-app-router-integration)
- [Monitor Mode vs. Protect Mode](#monitor-mode-vs-protect-mode)
- [Configuration Reference](#configuration-reference)
- [Rate Limiting & HTTP Headers](#rate-limiting--http-headers)
- [Programmatic Block API](#programmatic-block-api)
- [Local Security Event Logging (.jsonl)](#local-security-event-logging-jsonl)
- [Z-Shield CLI](#z-shield-cli)
  - [CLI Commands](#cli-commands)
  - [Process-Local Architecture Notice](#process-local-architecture-notice)
- [Client IP & Reverse Proxy Security](#client-ip--reverse-proxy-security)
- [Known Limitations](#known-limitations)
- [Running Tests & Examples](#running-tests--examples)
- [Troubleshooting](#troubleshooting)
- [Security Disclosures](#security-disclosures)
- [License](#license)

---

## What is Z-Shield?

**Z-Shield** is a self-contained, privacy-focused security toolkit for Node.js backends. It intercepts incoming HTTP requests, tracks request volume per IP in bounded server memory, enforces rate limits, logs security violations locally, and provides a CLI for inspecting live and historical security events.

It operates entirely locally with **zero external runtime dependencies**—no databases, no Redis clusters, no online dashboards, and no cloud telemetry required.

### What Z-Shield Does
- **Request Monitoring**: Tracks client requests by IP using a sliding time window.
- **Abuse Detection**: Detects traffic bursts exceeding your configured threshold.
- **Flexible Enforcement**:
  - **Monitor Mode**: Detects violations, logs them, attaches warning headers, but lets requests through unharmed.
  - **Protect Mode**: Enforces rate limits by rejecting offending requests with `HTTP 429 Too Many Requests` and a standard `Retry-After` header.
- **Temporary IP Blocking**: Supports time-based temporary IP bans with automatic expiration.
- **Safe Local Logging**: Writes structured security events to local JSON Lines (`.jsonl`) files with built-in log rotation and retention limits.
- **Log Injection Defense**: Sanitizes all untrusted input (routes, IPs, user agents) to prevent Log Injection (CWE-117) and terminal escape code exploits.
- **Privacy Protection**: Strictly ignores sensitive data—passwords, cookies, authorization tokens, and request bodies are never recorded (CWE-532).
- **DoS Memory Bounds**: Uses an LRU (Least Recently Used) cache strategy so an attacker cannot flood arbitrary IPs to exhaust server RAM.
- **Developer CLI**: Inspect status, view recent logs, and stream real-time events via `npx z-shield`.

### What Z-Shield Does NOT Do
- It is **not a full Web Application Firewall (WAF)** (it does not inspect SQL queries or deep packet payloads).
- It is **not a distributed rate limiter** (counters and temporary blocks are process-local to the single Node.js instance).
- It does **not prevent DDoS attacks** at the network/transport layer (L3/L4 volumetric attacks must be mitigated by cloud providers like Cloudflare, AWS Shield, etc.).
- It does **not authenticate users** or replace application login logic.

---

## Requirements & Installation

- **Node.js**: Version `18.0.0` or higher (uses built-in `node:test`, `node:assert`, `node:fs/promises`, and `node:net`).
- **Express**: Version `4.x` or higher.

Install Z-Shield into your project via npm:

```bash
npm install z-shield
```

*(Note: Z-Shield has 0 external runtime dependencies).*

---

## Quick Start: Express Integration

Here is a minimal, complete example showing how to mount Z-Shield in an Express application:

```javascript
'use strict';

const express = require('express');
const { createShield } = require('z-shield');

const app = express();

// 1. Initialize Z-Shield with your settings
const shield = createShield({
  appName: 'my-api',
  mode: 'protect',          // 'monitor' (log only) or 'protect' (enforce 429)
  windowMs: 60 * 1000,      // 1 minute window
  maxRequests: 100,         // 100 requests per minute per IP
  excludeRoutes: ['/health']// Routes that bypass rate limiting
});

// 2. Mount Z-Shield middleware as early as possible in your pipeline
app.use(shield.middleware);

// 3. Define your routes
app.get('/', (req, res) => {
  res.json({ message: 'Hello from Z-Shield protected API!' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});
```

---

## Quick Start: Next.js App Router Integration

Z-Shield provides native compatibility for Next.js App Router route handlers (`app/api/.../route.ts`) using Web-standard `Request` and `Response` objects.

```typescript
// app/api/protected/route.ts
import { withNextShield } from 'z-shield';

// CRITICAL: Z-Shield requires the Node.js runtime for file-based event logging.
// It cannot run in the Edge runtime.
export const runtime = 'nodejs';

export const GET = withNextShield(
  async (request: Request) => {
    return Response.json({
      success: true,
      message: 'Access granted to protected Next.js API route'
    });
  },
  {
    mode: 'protect',
    maxRequests: 50,
    windowMs: 60000,
    // Enable trustProxy and select your trusted reverse-proxy strategy
    trustProxy: true,
    getIp: 'cloudflare', // 'cloudflare' | 'x-real-ip' | 'x-forwarded-for' | 'akamai' | (req) => ...
    appName: 'my-nextjs-app'
  }
);
```

### Next.js Architectural Notes
- **Node.js Runtime Requirement**: Z-Shield relies on Node.js filesystem APIs for non-blocking JSONL event logging and `node:net` for strict IP validation. Always declare `export const runtime = 'nodejs';`.
- **Trusted Proxies & `getIp` Strategy**:
  When deploying behind reverse proxies, set `trustProxy: true` AND explicitly specify your provider's extraction strategy using `getIp`:
  - `'cloudflare'` / `'cf-connecting-ip'`: Inspects only `CF-Connecting-IP`.
  - `'nginx'` / `'x-real-ip'`: Inspects only `X-Real-IP`.
  - `'akamai'` / `'true-client-ip'`: Inspects only `True-Client-IP`.
  - `'x-forwarded-for'`: Inspects the first valid IP from `X-Forwarded-For` (requires outermost reverse proxy to strip or sanitize client-provided headers).
  - Custom function: `getIp: (req) => string | null | undefined`.
  *Fail-Safe Behavior*: If `trustProxy: true` is configured without specifying a `getIp` strategy, Z-Shield strictly refuses to guess across foreign proxy headers and safely falls back to `'unknown'` (or direct TCP socket if available). Unconfigured reverse-proxy headers and unverified platform properties are never trusted.
- **Process-Local Memory in Serverless**: Rate limit counters and temporary IP blocks are stored in-memory per Node.js process (bounded by LRU). In serverless environments, each active instance tracks traffic locally.

---

## Monitor Mode vs. Protect Mode

Z-Shield provides two operational modes:

| Feature | `mode: 'monitor'` | `mode: 'protect'` |
| :--- | :--- | :--- |
| **Normal Traffic** | Passes through (`HTTP 200`) | Passes through (`HTTP 200`) |
| **Threshold Exceeded** | Passes through (`HTTP 200`) | Blocked (`HTTP 429 Too Many Requests`) |
| **Active Blocked IP** | Passes through (`HTTP 200`) | Blocked (`HTTP 429 Too Many Requests`) |
| **Warning Headers** | `X-Z-Shield-Suspicious: 1` | `X-Z-Shield-Suspicious: 1` |
| **Action Logged** | `"action": "warned"` | `"action": "blocked"` |
| **Best Used For** | Initial deployment, tuning limits, traffic audits | Active production defense against brute force and scraping |

---

## Configuration Reference

Pass an options object to `createShield(options)`. All settings are validated and frozen at startup:

```javascript
const shield = createShield({
  // Unique application name (alphanumeric, dashes, underscores only)
  appName: 'default-app',

  // Operational mode: 'monitor' or 'protect'
  mode: 'monitor',

  // Duration of rate-limiting window in milliseconds (default: 1 minute)
  windowMs: 60 * 1000,

  // Maximum requests allowed per IP within windowMs
  maxRequests: 100,

  // Maximum unique client IPs tracked simultaneously in memory (DoS defense)
  maxTrackedIps: 10000,

  // Directory for JSON Lines event logs
  logDir: path.join(process.cwd(), '.z-shield-logs'),

  // Filename for active event log
  logFilename: 'events.jsonl',

  // Max size in bytes before rotating log file (default: 5MB)
  maxLogSizeBytes: 5 * 1024 * 1024,

  // Number of rotated log files to retain
  maxLogFiles: 5,

  // Default duration for temporary blocks (default: 15 minutes)
  blockDurationMs: 15 * 60 * 1000,

  // Max blocked IPs to keep in memory simultaneously
  maxBlockedIps: 5000,

  // Automatically place IP on temporary block list when rate limit is exceeded
  autoBlock: false,

  // Whether to trust reverse-proxy headers (e.g. X-Forwarded-For)
  // WARNING: Set to true only if behind a verified reverse proxy.
  // In Next.js App Router, also pair with 'getIp' strategy (e.g. 'cloudflare', 'nginx', 'x-forwarded-for')
  trustProxy: false,

  // Array of route prefixes that bypass tracking
  excludeRoutes: ['/health', '/favicon.ico'],

  // Maximum number of pending asynchronous log writes allowed in memory before dropping
  maxLogQueueSize: 1000,

  // Optional custom error callback for failed log writes: (err, event) => void
  onLogError: null
});
```

---

## Rate Limiting & HTTP Headers

Every request processed by Z-Shield receives informative, RFC-aligned HTTP response headers:

| Header | Description | Example |
| :--- | :--- | :--- |
| `X-Z-Shield-Protected` | Confirms Z-Shield middleware processed the request | `1` |
| `X-Z-Shield-Mode` | Active operational mode | `protect` or `monitor` |
| `X-RateLimit-Limit` | Maximum allowed requests per window | `100` |
| `X-RateLimit-Remaining` | Remaining requests allowed in current window | `42` |
| `X-RateLimit-Reset` | Unix timestamp (seconds) when the window resets | `1792412398` |
| `X-Z-Shield-Suspicious` | Set to `1` if threshold was exceeded or IP is flagged | `1` |
| `X-Z-Shield-Blocked` | Set to `1` if request was stopped due to an active block | `1` |
| `Retry-After` | Seconds client must wait before retrying (sent on 429) | `30` |

### Blocked Response Body (HTTP 429)
When a request is blocked in `protect` mode, Z-Shield immediately responds with status `429` and terminates processing:

```json
{
  "error": "Too Many Requests",
  "message": "Request threshold exceeded. Please try again later.",
  "retryAfter": 30
}
```

---

## Programmatic Block API

You can programmatically manage blocks in your Node.js code via the `shield` instance. No unauthenticated network endpoints are created:

```javascript
// Temporarily block an IP (supports milliseconds or strings like '30s', '10m', '1h', '2d')
shield.block('198.51.100.1', '10m', 'Repeated failed login attempts');

// Manually unblock an IP
shield.unblock('198.51.100.1');

// Check if an IP is currently blocked (returns boolean)
const isBlocked = shield.isBlocked('198.51.100.1');

// Retrieve block details (or null if not blocked)
const info = shield.getBlockInfo('198.51.100.1');
// Returns: { ip: '198.51.100.1', blockedAt: ..., expiresAt: ..., remainingMs: ..., reason: '...' }

// List all active blocks
const activeBlocks = shield.listBlocks();
```

---

## Local Security Event Logging (.jsonl)

Z-Shield automatically logs security events (rate limit breaches, blocks, warnings, and manual actions) to a local JSON Lines file:

**Default path**: `.z-shield-logs/events.jsonl`

### Example Log Record:
```json
{
  "timestamp": "2026-10-19T12:28:23.726Z",
  "appName": "my-api",
  "type": "rate_limit",
  "severity": "warning",
  "ip": "198.51.100.1",
  "method": "POST",
  "route": "/api/login",
  "reason": "Request threshold exceeded (6/5 in 30s)",
  "action": "blocked"
}
```

### Log Rotation & Retention
- When `events.jsonl` reaches `maxLogSizeBytes` (default: 5MB), Z-Shield rotates it to `events.1.jsonl`.
- Up to `maxLogFiles` (default: 5) historical files are preserved. Older files beyond the retention limit are automatically deleted.
- Log writes are executed in a sequential non-blocking queue, preventing file corruption under heavy concurrency.

---

## Z-Shield CLI

Z-Shield provides a built-in terminal CLI to inspect and monitor security events.

### CLI Commands

Run these commands in a separate terminal:

#### 1. View Security Status & Top Offenders
```bash
npx z-shield status
```
Shows total events, action counts (`BLOCKED`, `WARNED`), top targeted routes, and top offending IP addresses.

#### 2. View Recent Event Logs
```bash
# View last 20 events (default)
npx z-shield logs

# View last 50 events
npx z-shield logs --limit 50
```

#### 3. Real-Time Security Event Stream (`monitor`)
```bash
npx z-shield monitor
```
Tails the `.jsonl` log file and streams new security events in real time. Press `Ctrl+C` to exit cleanly.

#### 4. Block / Unblock Commands
```bash
npx z-shield block 198.51.100.1 --duration 10m
npx z-shield unblock 198.51.100.1
```

### Log Directory Resolution & Environment Variables
By default, the CLI looks for logs in `.z-shield-logs/events.jsonl` in your current working directory. You can customize the log directory using either the CLI flag or environment variable:

1. **CLI Flag (`--log-dir`)** (Highest precedence):
   ```bash
   npx z-shield status --log-dir /var/log/my-app
   npx z-shield logs --log-dir /var/log/my-app
   ```
2. **Environment Variable (`Z_SHIELD_LOG_DIR`)** (Second precedence):
   ```bash
   export Z_SHIELD_LOG_DIR=/var/log/my-app
   npx z-shield status
   ```
3. **Default Location** (Fallback):
   `./.z-shield-logs/events.jsonl`

When no log file is found, the CLI prints a helpful status message with the checked path and guidance on how to run your application or specify custom paths.

### Process-Local Architecture Notice
Z-Shield stores active IP counters and temporary blocks **in server memory (RAM)** inside your Express or Next.js application process.

Because the CLI runs in an independent Node.js process, it cannot reach into your running application's memory heap to alter active in-memory counters. When you execute `npx z-shield block`, the CLI:
1. Validates the IP and duration.
2. Writes an audit entry to the active security log file.
3. Displays the exact programmatic snippet to invoke inside your application code (`shield.block(...)`).

---

## Client IP & Reverse Proxy Security

### The Spoofing Risk
HTTP headers like `X-Forwarded-For` can be trivially forged by any client:
```bash
curl -H "X-Forwarded-For: 1.1.1.1" https://your-api.com
```
If your application blindly trusts `X-Forwarded-For`, an attacker could rotate fake IP headers on every request to bypass all rate limits and temporary blocks.

### Z-Shield Anti-Spoofing Rules
1. **`trustProxy: false` (Default)**: Z-Shield **completely ignores** `X-Forwarded-For` and inspects the raw TCP socket connection IP (`req.socket.remoteAddress`).
2. **`trustProxy: true`**: Z-Shield relies on Express's validated `req.ip`. You **must** configure Express's proxy policy correctly:

```javascript
const app = express();

// Configure Express trust proxy for your specific reverse proxy setup
// See Express documentation: http://expressjs.com/en/guide/behind-proxies.html
app.set('trust proxy', 'loopback'); // or specific IP of your Nginx / AWS ALB

const shield = createShield({
  trustProxy: true // Safe only because Express trust proxy is configured above
});
app.use(shield.middleware);
```

### Next.js Client IP Extraction & Reverse Proxy Requirements
In Next.js App Router route handlers, standard Web `Request` objects do not carry Node.js TCP sockets. Z-Shield enforces the following security model:

1. **`trustProxy: false` (Default)**:
   - Untrusted reverse-proxy headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`, etc.) and unverified platform properties are strictly ignored to prevent client IP spoofing attacks.
   - If a direct Node.js TCP socket is available (`req.socket.remoteAddress`), it is used.
   - **Deployment Limitation**: In environments without a direct TCP socket (e.g. serverless functions without trusted proxies), safe client IP identification cannot be guaranteed, and Z-Shield safely falls back to `'unknown'`.

2. **`trustProxy: true`**:
   - To prevent forged header injection across reverse proxies (e.g. an attacker sending `CF-Connecting-IP` to an Nginx server that passes unmanaged headers through), Z-Shield **strictly requires selecting an explicit trusted proxy strategy via `getIp`** (or providing a custom function):
     - `'cloudflare'` | `'cf-connecting-ip'`: Inspects only `CF-Connecting-IP` and strictly ignores all other proxy headers.
     - `'nginx'` | `'x-real-ip'`: Inspects only `X-Real-IP` and strictly ignores all other proxy headers.
     - `'akamai'` | `'true-client-ip'`: Inspects only `True-Client-IP` and strictly ignores all other proxy headers.
     - `'x-forwarded-for'`: Inspects only `X-Forwarded-For`, parsing candidates and taking the first valid IP.
     - Custom extractor: `(req: Request) => string | null | undefined`.
   - **Crucial Reverse-Proxy Requirement**: When using `'x-forwarded-for'` with an appending reverse proxy (such as default Nginx `$proxy_add_x_forwarded_for`), your edge proxy **MUST** strip client-supplied `X-Forwarded-For` headers at network ingress; otherwise, an attacker can prepend a forged IP. If your proxy cannot strip incoming headers, configure `'x-real-ip'` or provide a custom `getIp` function.
   - **Fail-Safe Behavior**: If `trustProxy: true` is configured without specifying `getIp`, Z-Shield strictly refuses to guess which header is authentic, and safely falls back to `'unknown'` (or direct TCP socket if available). Unconfigured reverse-proxy headers and unverified platform properties are never trusted.

> [!WARNING]
> **CRITICAL: The Serverless `'unknown'` Shared Bucket Trap**
>
> In serverless environments (Vercel Serverless Functions, AWS Lambda, Cloudflare Pages), requests arrive without an underlying direct Node.js TCP socket.
>
> If you leave `trustProxy: false` (or set `trustProxy: true` without a valid `getIp`), all incoming client IPs evaluate to `'unknown'`. Consequently, **all global visitors share one single rate-limit counter**. If `maxRequests` is exceeded or `autoBlock: true` triggers on `'unknown'`, **EVERY visitor worldwide will receive HTTP 429**, causing a self-inflicted Denial of Service (DoS) of your entire serverless API.
>
> **Remedy**: Always set `trustProxy: true` and specify the `getIp` strategy matching your hosting infrastructure:
>
> ```typescript
> // Vercel: Vercel edge strips/sanitizes X-Forwarded-For at ingress
> getIp: 'x-forwarded-for' // or 'x-real-ip'
>
> // Cloudflare: When application is strictly behind Cloudflare
> getIp: 'cloudflare' // strictly inspects CF-Connecting-IP
>
> // AWS CloudFront / ALB:
> getIp: (req) => req.headers.get('cloudfront-viewer-address')?.split(':')[0]
>   || req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
>
> // Nginx Reverse Proxy (configured with proxy_set_header X-Real-IP $remote_addr):
> getIp: 'nginx' // strictly inspects X-Real-IP
> ```

> [!CAUTION]
> **Proxy Headers Are Trustworthy ONLY When Your Infrastructure Sanitizes Them**
>
> **No single proxy strategy is safe for every hosting provider!** HTTP headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`, `True-Client-IP`) are untrusted client metadata unless your hosting proxy explicitly sets or sanitizes them.
>
> Never configure a strategy that does not match your actual ingress infrastructure (e.g. configuring `getIp: 'cloudflare'` on AWS or Bare Metal without Cloudflare allows anyone on the internet to send a forged `CF-Connecting-IP` header). Furthermore, always ensure direct origin access is firewalled so traffic cannot bypass your proxy.

---

## Known Limitations

We believe in full engineering transparency:

1. **Process-Local Memory**:
   - In this release, counters and active blocks reside in the Node.js process heap.
   - If you run multiple server instances or multiple Node.js cluster workers, counters are not shared across processes. (A distributed Redis adapter is planned for a future release).
2. **Restarts Reset Memory**:
   - When your Node.js application process restarts or crashes, in-memory counters and temporary blocks reset. (Historical event logs in `.z-shield-logs/events.jsonl` persist on disk).
3. **Fixed-Window Boundary Burst**:
   - Z-Shield uses a fixed window per IP. If an IP sends 100 requests right before the window expires, and 100 requests immediately after it resets, 200 requests pass in a short span without exceeding either window limit.
4. **Ephemeral Hosting Filesystems**:
   - On serverless platforms or ephemeral container dynos (such as basic Heroku or AWS Lambda), local `.z-shield-logs` files will be reset upon container termination. Persistent volume mounts are recommended for persistent auditing.

---

## Running Tests & Examples

### Automated Test Suite
Z-Shield includes comprehensive unit and integration tests using Node.js's built-in `node:test` and `node:assert`:

```bash
npm test
```

### Running the Demo Application
Start the runnable Express demo:

```bash
npm start
```
*(Runs at `http://localhost:3000` with rate limit set to 5 requests per 30s for easy testing).*

Test hitting the limit in a second terminal:
```bash
for i in {1..6}; do curl -s -i http://localhost:3000/ | head -n 8; echo "---"; done
```

To run the demo in monitor mode instead:
```bash
SHIELD_MODE=monitor npm start
```

---

## Troubleshooting

### Q: Why do all requests seem to come from `127.0.0.1`?
**A**: When testing locally, `127.0.0.1` is your loopback address. In production behind a reverse proxy (like Nginx), make sure you configured `app.set('trust proxy', ...)` in Express and set `trustProxy: true` in Z-Shield.

### Q: Why did an IP get blocked in one worker but allowed in another?
**A**: Node.js cluster workers run in separate processes with isolated memory heaps. Each worker maintains its own in-memory counter.

### Q: Why did `npx z-shield status` say "No log file found yet"?
**A**: The `.z-shield-logs/events.jsonl` file is created automatically when the first security violation occurs. Start your server and trigger a threshold violation to generate log data.

---

## Security Disclosures

For vulnerability disclosures and reporting procedures, please refer to [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE) © 2026 zeesu-royalist
