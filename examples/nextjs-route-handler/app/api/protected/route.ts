/**
 * Next.js App Router Route Handler with Z-Shield Protection
 *
 * Location: app/api/protected/route.ts
 */

import { withNextShield, createNextShield } from 'z-shield';

// CRITICAL: Z-Shield requires the Node.js runtime for file-based JSONL logging
// and socket IP inspection. It cannot run in the Edge runtime.
export const runtime = 'nodejs';

/**
 * ============================================================================
 * CRITICAL SERVERLESS NOTICE: The 'unknown' Shared Bucket Trap
 * ============================================================================
 * In serverless environments (Vercel, AWS Lambda, Cloudflare Pages), standard Web
 * Request objects have NO direct TCP socket (socket.remoteAddress is undefined).
 *
 * - If trustProxy: false (default), or if trustProxy: true without getIp,
 *   all client IPs resolve to 'unknown'.
 * - In protect mode, if 'unknown' exceeds maxRequests or triggers autoBlock,
 *   EVERY visitor worldwide is locked out with HTTP 429 simultaneously!
 *
 * REMEDY: In serverless deployments, always set trustProxy: true AND configure
 * the getIp strategy matching your actual hosting proxy infrastructure.
 *
 * PROXY SECURITY WARNING:
 * Proxy headers (CF-Connecting-IP, X-Real-IP, X-Forwarded-For) are trustworthy
 * ONLY if your hosting infrastructure actively sanitizes or sets them at the edge,
 * and direct origin connections bypassing the proxy are firewalled.
 * ============================================================================
 */

// Option 1: Using higher-order withNextShield wrapper
// Example configured for Vercel deployment (Vercel sanitizes X-Forwarded-For at ingress)
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
    appName: 'my-nextjs-app',

    // In serverless, enable proxy trust and specify the strategy matching your proxy:
    trustProxy: true,

    // Select the strategy that matches your hosting environment:
    // - Vercel: 'x-forwarded-for' (or 'x-real-ip')
    // - Cloudflare: 'cloudflare' (strictly inspects CF-Connecting-IP)
    // - Nginx: 'nginx' (strictly inspects X-Real-IP)
    // - AWS CloudFront: (req) => req.headers.get('cloudfront-viewer-address')?.split(':')[0]
    getIp: 'x-forwarded-for'
  }
);

// Option 2: Using createNextShield instance (e.g. Cloudflare or custom infrastructure)
const cloudflareShield = createNextShield({
  mode: 'protect',
  maxRequests: 20,
  windowMs: 60000,
  trustProxy: true,
  getIp: 'cloudflare', // Only safe if the app is strictly deployed behind Cloudflare!
  appName: 'my-nextjs-app'
});

export const POST = cloudflareShield.protect(async (request: Request) => {
  const body = await request.json().catch(() => ({}));
  return Response.json(
    {
      status: 'created',
      data: body
    },
    { status: 201 }
  );
});
