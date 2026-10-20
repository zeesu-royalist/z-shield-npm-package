/**
 * Next.js App Router Route Handler with Z-Shield Protection
 *
 * Location: app/api/protected/route.ts
 */

import { withNextShield, createNextShield } from 'z-shield';

// CRITICAL: Z-Shield requires the Node.js runtime for file-based JSONL logging
// and socket IP inspection. It cannot run in the Edge runtime.
export const runtime = 'nodejs';

// Option 1: Using higher-order withNextShield wrapper
export const GET = withNextShield(
  async (request: Request) => {
    return Response.json({
      success: true,
      message: 'Access granted to protected Next.js API route',
      timestamp: new Date().toISOString()
    });
  },
  {
    mode: 'protect',
    maxRequests: 50,
    windowMs: 60000, // 1 minute
    autoBlock: true,
    blockDurationMs: 600000, // 10 minutes
    // Set trustProxy to true when deployed behind a reverse proxy,
    // and explicitly specify your trusted proxy IP strategy:
    trustProxy: true,
    getIp: 'cloudflare', // 'cloudflare' | 'x-real-ip' | 'x-forwarded-for' | 'akamai' | (req) => ...
    appName: 'my-nextjs-app'
  }
);

// Option 2: Using createNextShield instance (for programmatic control and custom logic)
const shield = createNextShield({
  mode: 'protect',
  maxRequests: 20,
  windowMs: 60000,
  trustProxy: true,
  getIp: 'x-forwarded-for',
  appName: 'my-nextjs-app'
});

export const POST = shield.protect(async (request: Request) => {
  const body = await request.json().catch(() => ({}));
  return Response.json({
    status: 'created',
    data: body
  }, { status: 201 });
});
