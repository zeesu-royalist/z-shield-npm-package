<a id="top"></a>

# 🛡️ Z-Shield

> Lightweight, zero-dependency rate limiting, abuse detection, and IP protection for **Node.js**, **Express**, and **Next.js App Router**.
>
> 👨‍💻 Created by **[Zeesu Royalist](https://zeesu-royalist.vercel.app)** — [zeesu-royalist.vercel.app](https://zeesu-royalist.vercel.app)

[![Author: Zeesu Royalist](https://img.shields.io/badge/Author-Zeesu%20Royalist-0070f3.svg?logo=vercel&logoColor=white)](https://zeesu-royalist.vercel.app)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20runtime-blue.svg)](package.json)

---

## 📌 Quick Navigation (Jump to Section)

Click any link below to jump directly to that section:

- ⚡ [Features](#features)
- 📦 [Installation](#installation)
- 🚀 [1. Express.js Implementation (GET & POST)](#express)
- ⚡ [2. Next.js App Router Implementation](#nextjs)
  - 📄 [A. Static API Route: GET & POST](#nextjs-static)
  - 🔀 [B. Dynamic Route: `[id]` with Route Params](#nextjs-dynamic)
  - 🔄 [C. Reusable Instance (`createNextShield`)](#nextjs-instance)
  - 🌐 [D. Reverse Proxy & Hosting Guide (Vercel, Cloudflare, etc.)](#nextjs-proxies)
- 🛡️ [Operational Modes: Protect vs. Monitor](#modes)
- 🚫 [Programmatic IP Block API](#block-api)
- 📊 [CLI Tools (`npx z-shield`)](#cli)
- ⚙️ [Configuration Reference](#config)
- 📡 [HTTP Response Headers](#headers)
- 🧪 [Testing with `curl`](#testing)
- 📄 [License & Author](#license)

---

<a id="features"></a>
## ⚡ Features

- **Zero Dependencies**: Pure Node.js. No Redis, MongoDB, or external services required.
- **Express & Next.js Support**: Plug-and-play middleware for Express and route wrappers for Next.js App Router (`route.ts`).
- **Smart Rate Limiting**: Fixed window rate limiting with RFC-compliant headers (`Retry-After`, `X-RateLimit-*`).
- **Temporary IP Blocking**: Automatically or manually block abusive IPs for a set duration (e.g. `10m`, `1h`).
- **Two Modes**: `protect` (enforces HTTP 429) and `monitor` (logs only, no blocking).
- **Local Security Logs**: Non-blocking JSONL logging (`.z-shield-logs/events.jsonl`) with automatic log rotation.
- **Built-in CLI**: Inspect traffic, view top offending IPs, and stream live events with `npx z-shield`.

[⬆ Back to Top](#top)

---

<a id="installation"></a>
## 📦 Installation

```bash
npm install z-shield
```

*(Requires Node.js 18.0.0 or higher)*

[⬆ Back to Top](#top)

---

<a id="express"></a>
## 🚀 1. Express.js Implementation

Z-Shield easily integrates into Express as global middleware or per-route.

### Complete Express Example (GET & POST)

```javascript
// server.js
const express = require('express');
const { createShield } = require('z-shield');

const app = express();
app.use(express.json()); // Parse JSON request bodies for POST

// 1. Initialize Z-Shield
const shield = createShield({
  appName: 'my-api',
  mode: 'protect',                 // 'protect' = block with 429 | 'monitor' = log only
  windowMs: 60 * 1000,             // Time window: 1 minute (in milliseconds)
  maxRequests: 100,                // Max 100 requests per IP in windowMs
  blockDurationMs: 15 * 60 * 1000, // IP block duration: 15 minutes
  autoBlock: true,                 // Auto-block IP if it exceeds limit
  excludeRoutes: ['/health']       // Routes that bypass rate limiting
});

// 2. Attach Z-Shield middleware globally
app.use(shield.middleware);

// --- GET Route Example ---
app.get('/api/users', (req, res) => {
  // Access Z-Shield metadata via req.zShield
  res.json({
    success: true,
    users: [
      { id: 1, name: 'Alice' },
      { id: 2, name: 'Bob' }
    ]
  });
});

// --- POST Route Example ---
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Example: Manually block brute-force attempts
  if (username === 'admin' && password !== 'secret123') {
    shield.block(req.ip, '10m', 'Failed admin login attempt');
    return res.status(401).json({ error: 'Invalid credentials. IP temporarily blocked.' });
  }

  res.json({ success: true, message: 'Logged in successfully!' });
});

// --- Excluded Route (Never rate limited) ---
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Start the server
app.listen(3000, () => {
  console.log('🛡️ Server protected with Z-Shield on http://localhost:3000');
});
```

[⬆ Back to Top](#top)

---

<a id="nextjs"></a>
## ⚡ 2. Next.js App Router Implementation

Z-Shield provides native route handler wrappers (`withNextShield` and `createNextShield`) for Next.js App Router (`app/api/.../route.ts`).

> **Important**: Always include `export const runtime = 'nodejs';` in your API route because Z-Shield requires the Node.js runtime for file logging and IP extraction.

---

<a id="nextjs-static"></a>
### A. Static API Route: GET & POST (`app/api/posts/route.ts`)

```typescript
// app/api/posts/route.ts
import { withNextShield } from 'z-shield';

// Required: Runs in Node.js runtime (not Edge)
export const runtime = 'nodejs';

// Shared protection configuration
const shieldConfig = {
  mode: 'protect',
  maxRequests: 50,                 // 50 requests
  windowMs: 60 * 1000,             // per 1 minute
  autoBlock: true,
  blockDurationMs: 10 * 60 * 1000, // 10 minutes block
  trustProxy: true,                // Required for serverless deployments (Vercel, etc.)
  getIp: 'x-forwarded-for'         // Strategy for Vercel/proxies
};

// --- GET Request Handler ---
export const GET = withNextShield(async (request: Request) => {
  return Response.json({
    success: true,
    posts: [
      { id: 1, title: 'Introduction to Z-Shield' },
      { id: 2, title: 'Securing Next.js APIs' }
    ]
  });
}, shieldConfig);

// --- POST Request Handler ---
export const POST = withNextShield(async (request: Request) => {
  // Read request body safely
  const body = await request.json().catch(() => ({}));

  return Response.json(
    {
      success: true,
      message: 'Post created successfully',
      data: body
    },
    { status: 201 }
  );
}, shieldConfig);
```

[⬆ Back to Top](#top)

---

<a id="nextjs-dynamic"></a>
### B. Dynamic Route: `[id]` with Route Params (`app/api/users/[id]/route.ts`)

Dynamic route parameters (`params`) pass smoothly into `withNextShield`:

```typescript
// app/api/users/[id]/route.ts
import { withNextShield } from 'z-shield';

export const runtime = 'nodejs';

// Protection options
const shieldConfig = {
  mode: 'protect',
  maxRequests: 30,
  windowMs: 60 * 1000,
  trustProxy: true,
  getIp: 'x-forwarded-for'
};

// --- GET /api/users/:id ---
export const GET = withNextShield(async (request, context: { params: Promise<{ id: string }> }) => {
  // Compatible with both Next.js 14 and Next.js 15 (await params)
  const { id } = await context.params;

  return Response.json({
    success: true,
    user: { id, name: `User ${id}`, role: 'Developer' }
  });
}, shieldConfig);

// --- POST /api/users/:id ---
export const POST = withNextShield(async (request, context: { params: Promise<{ id: string }> }) => {
  const { id } = await context.params;
  const body = await request.json().catch(() => ({}));

  return Response.json({
    success: true,
    message: `User ${id} updated`,
    updatedData: body
  });
}, shieldConfig);
```

[⬆ Back to Top](#top)

---

<a id="nextjs-instance"></a>
### C. Reusable Instance (`createNextShield`)

If you prefer defining a single shield instance and reusing it across handlers:

```typescript
// app/api/example/route.ts
import { createNextShield } from 'z-shield';

export const runtime = 'nodejs';

// 1. Create a reusable shield instance
const shield = createNextShield({
  mode: 'protect',
  maxRequests: 20,
  windowMs: 60 * 1000,
  trustProxy: true,
  getIp: 'x-forwarded-for'
});

// 2. Protect handlers using shield.protect()
export const GET = shield.protect(async (request: Request) => {
  return Response.json({ message: 'Protected using createNextShield' });
});
```

[⬆ Back to Top](#top)

---

<a id="nextjs-proxies"></a>
### D. Reverse Proxy & Hosting Guide for Next.js

In serverless platforms (Vercel, AWS Lambda, Cloudflare), client requests don't have direct TCP sockets. Always enable `trustProxy: true` and specify the matching `getIp` strategy:

| Hosting Provider | `trustProxy` | `getIp` Strategy |
| :--- | :--- | :--- |
| **Vercel** | `true` | `'x-forwarded-for'` (or `'x-real-ip'`) |
| **Cloudflare** | `true` | `'cloudflare'` (inspects `CF-Connecting-IP`) |
| **Nginx** | `true` | `'nginx'` (inspects `X-Real-IP`) |
| **AWS CloudFront / ALB** | `true` | `(req) => req.headers.get('cloudfront-viewer-address')?.split(':')[0]` |
| **Localhost / Bare Metal** | `false` | *(Omit or leave default)* |

[⬆ Back to Top](#top)

---

<a id="modes"></a>
## 🛡️ Operational Modes: Protect vs. Monitor

| Feature | `mode: 'protect'` | `mode: 'monitor'` |
| :--- | :--- | :--- |
| **Normal Traffic** | Passes through (`HTTP 200`) | Passes through (`HTTP 200`) |
| **Rate Limit Exceeded** | Blocked with **`HTTP 429`** | Allowed (`HTTP 200`) + Warning Header |
| **Blocked IP** | Blocked with **`HTTP 429`** | Allowed (`HTTP 200`) + Warning Header |
| **Logged Action** | `"action": "blocked"` | `"action": "warned"` |
| **Best Used For** | **Active production defense** | **Testing & audit without breaking users** |

[⬆ Back to Top](#top)

---

<a id="block-api"></a>
## 🚫 Programmatic IP Block API

Manage IP blocks directly inside your application code:

```javascript
// Block an IP for 10 minutes with a custom reason (supports '30s', '10m', '1h', '2d')
shield.block('198.51.100.1', '10m', 'Suspicious activity');

// Check if an IP is currently blocked (returns true or false)
const blocked = shield.isBlocked('198.51.100.1');

// Get block details (remaining time, reason, expiry)
const info = shield.getBlockInfo('198.51.100.1');

// Unblock an IP immediately and reset its rate limiter
shield.unblock('198.51.100.1');

// List all currently active blocks
const activeBlocks = shield.listBlocks();
```

[⬆ Back to Top](#top)

---

<a id="cli"></a>
## 📊 CLI Tools

Z-Shield includes a built-in CLI for inspecting logs and traffic stats:

```bash
# 1. View security overview, total blocks, and top offender IPs
npx z-shield status

# 2. View recent security event logs
npx z-shield logs --limit 30

# 3. Stream real-time security events (live tail)
npx z-shield monitor

# 4. View CLI help and all options
npx z-shield --help
```

[⬆ Back to Top](#top)

---

<a id="config"></a>
## ⚙️ Configuration Reference

All options can be passed to `createShield(options)` or `createNextShield(options)`:

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `appName` | `string` | `'default-app'` | Identifier for your application in log files. |
| `mode` | `'protect' \| 'monitor'` | `'monitor'` | `'protect'` returns HTTP 429; `'monitor'` logs only. |
| `windowMs` | `number` | `60000` (1 min) | Time window in milliseconds for tracking requests. |
| `maxRequests` | `number` | `100` | Maximum requests allowed per IP within `windowMs`. |
| `blockDurationMs` | `number` | `900000` (15 min) | Duration of temporary IP block in milliseconds. |
| `autoBlock` | `boolean` | `false` | Automatically blocks an IP when it exceeds `maxRequests`. |
| `excludeRoutes` | `string[]` | `['/health', '/favicon.ico']` | Routes that skip all rate limiting and blocking. |
| `trustProxy` | `boolean` | `false` | Set to `true` when running behind a reverse proxy/serverless. |
| `getIp` | `string \| function` | `undefined` | Proxy IP strategy (`'x-forwarded-for'`, `'cloudflare'`, etc.). |
| `logDir` | `string` | `'.z-shield-logs'` | Directory where JSONL logs are saved. |
| `maxTrackedIps` | `number` | `10000` | Max distinct IPs held in memory (bounded LRU to prevent memory DoS). |

[⬆ Back to Top](#top)

---

<a id="headers"></a>
## 📡 HTTP Response Headers

Z-Shield automatically adds security and rate limit headers to responses:

| Header | Example | Description |
| :--- | :--- | :--- |
| `X-Z-Shield-Protected` | `1` | Confirms request was processed by Z-Shield. |
| `X-Z-Shield-Mode` | `protect` | Current operating mode (`protect` or `monitor`). |
| `X-RateLimit-Limit` | `100` | Max requests allowed in the current time window. |
| `X-RateLimit-Remaining` | `42` | Requests remaining for the client in this window. |
| `X-RateLimit-Reset` | `1792412398` | Epoch timestamp (in seconds) when window resets. |
| `X-Z-Shield-Suspicious` | `1` | Present if request exceeded limits or triggered warnings. |
| `X-Z-Shield-Blocked` | `1` | Present if the request was blocked with HTTP 429. |
| `Retry-After` | `30` | Seconds the client must wait before retrying (sent on 429). |

### HTTP 429 Blocked Response Body

```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Please wait before retrying.",
  "retryAfter": 30
}
```

[⬆ Back to Top](#top)

---

<a id="testing"></a>
## 🧪 Testing the Protection

You can test your protected server easily using `curl`:

```bash
# Send 6 rapid requests to see HTTP 429 in action
for i in {1..6}; do curl -i http://localhost:3000/api/users; done
```

[⬆ Back to Top](#top)

---

<a id="license"></a>
## 📄 License & Author

- **Author**: [Zeesu Royalist](https://zeesu-royalist.vercel.app)
- **Website**: [zeesu-royalist.vercel.app](https://zeesu-royalist.vercel.app)
- **License**: [MIT](LICENSE) © 2026 Zeesu Royalist

[⬆ Back to Top](#top)
