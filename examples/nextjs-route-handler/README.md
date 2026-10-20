# Z-Shield Next.js App Router Integration Example

This example demonstrates how to integrate `z-shield` into Next.js App Router route handlers (`app/api/.../route.ts`).

---

## 1. Quick Start

Install `z-shield`:
```bash
npm install z-shield
```

In your Next.js API route handler (`app/api/protected/route.ts`):

```typescript
import { withNextShield } from 'z-shield';

// 1. Mandatory runtime declaration
export const runtime = 'nodejs';

// 2. Wrap your route handler
export const GET = withNextShield(
  async (request: Request) => {
    return Response.json({ message: 'Hello from secure API' });
  },
  {
    mode: 'protect',
    maxRequests: 60,
    windowMs: 60000,
    trustProxy: true, // Enable when hosted behind reverse proxies
    getIp: 'cloudflare', // Explicitly select your trusted proxy strategy
    appName: 'my-nextjs-app'
  }
);
```

---

## 2. Important Architectural Considerations

### Node.js Runtime Requirement
Z-Shield uses Node.js native filesystem capabilities (`node:fs`) for persistent, non-blocking JSONL security event logging and rotation, as well as `node:net` for strict IP validation and normalization.

Because the Next.js Edge runtime does not provide Node.js `fs` APIs, **you must configure the route handler to use the Node.js runtime**:

```typescript
export const runtime = 'nodejs';
```

If you deploy to Vercel or AWS, serverless functions run in Node.js by default unless `runtime = 'edge'` is explicitly specified.

---

### Trusted Proxy & Client IP Extraction

When Next.js runs behind reverse proxies or hosting infrastructure (such as Cloudflare, Nginx, Akamai, or AWS), the direct TCP socket address reflects the proxy rather than the end client.

* **When `trustProxy: false` (Default)**:
  All proxy headers and unverified platform properties are strictly ignored to prevent client IP spoofing. Only direct TCP socket remote addresses (`socket.remoteAddress`) are inspected. In environments without direct sockets (e.g. serverless functions without trusted proxies), client IP resolution safely falls back to `'unknown'`.

* **When `trustProxy: true`**:
  To protect against forged header injection across reverse proxies (e.g. an attacker sending `CF-Connecting-IP` to an Nginx server), Z-Shield **strictly requires explicitly selecting your proxy extraction strategy via `getIp`**:
  - `'cloudflare'` | `'cf-connecting-ip'`: Inspects only the `CF-Connecting-IP` header and ignores all other proxy headers.
  - `'nginx'` | `'x-real-ip'`: Inspects only the `X-Real-IP` header and ignores all other proxy headers.
  - `'akamai'` | `'true-client-ip'`: Inspects only the `True-Client-IP` header and ignores all other proxy headers.
  - `'x-forwarded-for'`: Inspects only the first valid IP from `X-Forwarded-For`. *Deployment requirement*: Ensure your outermost edge proxy strips or overwrites any client-supplied `X-Forwarded-For` header at ingress to prevent IP prepending.
  - Custom function: `(req: Request) => string | null | undefined`

* **Fail-Safe Behavior**:
  If `trustProxy: true` is configured without specifying a `getIp` strategy or function, Z-Shield strictly refuses to guess which header is authentic, and safely falls back to `'unknown'` (or direct TCP socket if available). It does not silently claim security or trust unverified headers.

Example with custom header extractor:

```typescript
const shield = createNextShield({
  mode: 'protect',
  trustProxy: true,
  getIp: (req) => req.headers.get('cloudfront-viewer-address')?.split(':')[0]
});
```

---

### Process-Local State in Serverless Environments
Z-Shield's `RateLimiter` and `BlockManager` maintain high-performance, process-local in-memory sliding windows with LRU bounded memory.

In serverless environments (such as Vercel Serverless Functions or AWS Lambda):
* Each active serverless function instance maintains its own in-memory state.
* Consecutive requests routed to the same warm instance share rate-limiting counters.
* Requests routed across multiple concurrent serverless instances increment their respective local counters.
* For multi-region serverless setups requiring global rate synchronization across disparate instances, Z-Shield acts as a fast, in-process first line of defense with local file audit logging.
