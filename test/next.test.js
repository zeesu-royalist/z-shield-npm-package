'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const {
  createNextShield,
  withNextShield,
  extractNextClientIp,
  createShield
} = require('../dist/index');

describe('Next.js App Router Compatibility Adapter', () => {
  let tempLogDir;
  let activeShields = [];

  const trackShield = (s) => {
    activeShields.push(s);
    return s;
  };

  beforeEach(() => {
    activeShields = [];
    tempLogDir = path.join(
      os.tmpdir(),
      `z-shield-next-test-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
  });

  afterEach(async () => {
    for (const s of activeShields) {
      try {
        await s.flush();
      } catch {}
    }
    if (fs.existsSync(tempLogDir)) {
      fs.rmSync(tempLogDir, { recursive: true, force: true });
    }
  });

  describe('Client IP Extraction (extractNextClientIp)', () => {
    test('extracts socket remoteAddress when trustProxy is false', () => {
      const reqWithSocket = { socket: { remoteAddress: '198.51.100.1' } };
      assert.equal(extractNextClientIp(reqWithSocket, false), '198.51.100.1');

      // When trustProxy is false and no socket exists, unverified req.ip is not trusted
      const reqWithIpOnly = { ip: '198.51.100.1' };
      assert.equal(extractNextClientIp(reqWithIpOnly, false), 'unknown');

      // When trustProxy is true without explicit getIp, unverified req.ip is also NOT trusted (fail-safe)
      assert.equal(extractNextClientIp(reqWithIpOnly, true), 'unknown');
    });

    test('ignores untrusted proxy headers when trustProxy is false', () => {
      const req = new Request('http://localhost/api/test', {
        headers: {
          'x-forwarded-for': '203.0.113.10',
          'x-real-ip': '203.0.113.11',
          'cf-connecting-ip': '203.0.113.12',
          'true-client-ip': '203.0.113.13'
        }
      });

      // Untrusted proxy headers must be ignored to prevent IP spoofing
      assert.equal(extractNextClientIp(req, false), 'unknown');

      // Even if a proxy strategy string is passed with trustProxy: false, headers are ignored
      assert.equal(extractNextClientIp(req, false, 'cloudflare'), 'unknown');
      assert.equal(extractNextClientIp(req, false, 'x-forwarded-for'), 'unknown');
    });

    test('fails safely when trustProxy is true but no getIp strategy is configured', () => {
      const req = new Request('http://localhost/api/test', {
        headers: {
          'cf-connecting-ip': '198.51.100.200',
          'x-real-ip': '198.51.100.201',
          'true-client-ip': '198.51.100.202',
          'x-forwarded-for': '203.0.113.50'
        }
      });

      // Must NOT guess or cascade across foreign headers; fails safely to 'unknown'
      assert.equal(extractNextClientIp(req, true), 'unknown');
      assert.equal(extractNextClientIp(req, true, undefined), 'unknown');
    });

    test('strategy isolation: cloudflare trusts only CF-Connecting-IP and rejects forged headers', () => {
      const req = new Request('http://localhost/api/test', {
        headers: {
          'x-forwarded-for': '1.2.3.4, 5.6.7.8',
          'x-real-ip': '10.0.0.1',
          'true-client-ip': '172.16.0.1',
          'cf-connecting-ip': '198.51.100.200'
        }
      });

      // 'cloudflare' and 'cf-connecting-ip' extract only CF-Connecting-IP
      assert.equal(extractNextClientIp(req, true, 'cloudflare'), '198.51.100.200');
      assert.equal(extractNextClientIp(req, true, 'cf-connecting-ip'), '198.51.100.200');

      // If CF-Connecting-IP is missing or invalid, must NOT fall back to other headers
      const reqForgedOnly = new Request('http://localhost/api/test', {
        headers: {
          'x-forwarded-for': '1.2.3.4',
          'x-real-ip': '10.0.0.1'
        }
      });
      assert.equal(extractNextClientIp(reqForgedOnly, true, 'cloudflare'), 'unknown');

      const reqInvalidCf = new Request('http://localhost/api/test', {
        headers: {
          'cf-connecting-ip': 'not-an-ip',
          'x-forwarded-for': '1.2.3.4'
        }
      });
      assert.equal(extractNextClientIp(reqInvalidCf, true, 'cloudflare'), 'unknown');
    });

    test('strategy isolation: nginx / x-real-ip trusts only X-Real-IP and rejects forged headers', () => {
      const req = new Request('http://localhost/api/test', {
        headers: {
          'cf-connecting-ip': '1.2.3.4',
          'true-client-ip': '5.6.7.8',
          'x-forwarded-for': '9.10.11.12',
          'x-real-ip': '198.51.100.201'
        }
      });

      // 'nginx' and 'x-real-ip' extract only X-Real-IP
      assert.equal(extractNextClientIp(req, true, 'nginx'), '198.51.100.201');
      assert.equal(extractNextClientIp(req, true, 'x-real-ip'), '198.51.100.201');

      // If X-Real-IP is missing or invalid, must NOT fall back to other headers
      const reqForgedOnly = new Request('http://localhost/api/test', {
        headers: {
          'cf-connecting-ip': '1.2.3.4',
          'x-forwarded-for': '9.10.11.12'
        }
      });
      assert.equal(extractNextClientIp(reqForgedOnly, true, 'nginx'), 'unknown');

      const reqInvalidReal = new Request('http://localhost/api/test', {
        headers: {
          'x-real-ip': 'invalid-ip',
          'cf-connecting-ip': '1.2.3.4'
        }
      });
      assert.equal(extractNextClientIp(reqInvalidReal, true, 'x-real-ip'), 'unknown');
    });

    test('strategy isolation: akamai / true-client-ip trusts only True-Client-IP and rejects forged headers', () => {
      const req = new Request('http://localhost/api/test', {
        headers: {
          'cf-connecting-ip': '1.2.3.4',
          'x-real-ip': '5.6.7.8',
          'x-forwarded-for': '9.10.11.12',
          'true-client-ip': '198.51.100.202'
        }
      });

      // 'akamai' and 'true-client-ip' extract only True-Client-IP
      assert.equal(extractNextClientIp(req, true, 'akamai'), '198.51.100.202');
      assert.equal(extractNextClientIp(req, true, 'true-client-ip'), '198.51.100.202');

      // If True-Client-IP is missing or invalid, must NOT fall back to other headers
      const reqForgedOnly = new Request('http://localhost/api/test', {
        headers: {
          'cf-connecting-ip': '1.2.3.4',
          'x-real-ip': '5.6.7.8'
        }
      });
      assert.equal(extractNextClientIp(reqForgedOnly, true, 'akamai'), 'unknown');

      const reqInvalidTrue = new Request('http://localhost/api/test', {
        headers: {
          'true-client-ip': 'malformed',
          'cf-connecting-ip': '1.2.3.4'
        }
      });
      assert.equal(extractNextClientIp(reqInvalidTrue, true, 'true-client-ip'), 'unknown');
    });

    test('strategy isolation: x-forwarded-for extracts first valid IP and rejects forged foreign headers', () => {
      // Normal multi-hop with forged CF and Real-IP headers present
      const reqValid = new Request('http://localhost/api/test', {
        headers: {
          'cf-connecting-ip': '1.1.1.1',
          'x-real-ip': '2.2.2.2',
          'x-forwarded-for': '203.0.113.50, 10.0.0.1, 172.16.0.1'
        }
      });
      assert.equal(extractNextClientIp(reqValid, true, 'x-forwarded-for'), '203.0.113.50');

      // Multi-value with leading whitespace
      const reqWhitespace = new Request('http://localhost/api/test', {
        headers: {
          'x-forwarded-for': '   203.0.113.55   , 10.0.0.1'
        }
      });
      assert.equal(extractNextClientIp(reqWhitespace, true, 'x-forwarded-for'), '203.0.113.55');

      // Attacker injected HTML / command / control characters into first candidate
      const reqMalformed = new Request('http://localhost/api/test', {
        headers: {
          'x-forwarded-for': '<script>alert(1)</script>, not-an-ip, 203.0.113.60, 10.0.0.1'
        }
      });
      assert.equal(extractNextClientIp(reqMalformed, true, 'x-forwarded-for'), '203.0.113.60');

      // Completely invalid x-forwarded-for falls back to socket or unknown
      const reqInvalid = new Request('http://localhost/api/test', {
        headers: {
          'cf-connecting-ip': '1.1.1.1',
          'x-forwarded-for': 'invalid, 999.999.999.999, corrupted'
        }
      });
      assert.equal(extractNextClientIp(reqInvalid, true, 'x-forwarded-for'), 'unknown');
    });

    test('normalizes IPv6-mapped IPv4 addresses', () => {
      const req = new Request('http://localhost/api/test', {
        headers: { 'x-forwarded-for': '::ffff:192.0.2.1' }
      });
      assert.equal(extractNextClientIp(req, true, 'x-forwarded-for'), '192.0.2.1');
    });

    test('custom getIp extractor takes precedence and validates return value', () => {
      const req = new Request('http://localhost/api/test', {
        headers: { 'x-custom-client': '198.51.100.22' }
      });

      const customExtractor = (r) => r.headers.get('x-custom-client');
      assert.equal(extractNextClientIp(req, false, customExtractor), '198.51.100.22');

      // Custom extractor returning invalid IP safely returns 'unknown'
      const invalidExtractor = () => 'invalid-ip-string';
      assert.equal(extractNextClientIp(req, true, invalidExtractor), 'unknown');

      // Custom extractor throwing safely returns 'unknown'
      const throwingExtractor = () => {
        throw new Error('extractor failure');
      };
      assert.equal(extractNextClientIp(req, true, throwingExtractor), 'unknown');
    });

    test('case-insensitivity on plain object headers across different proxy strategies', () => {
      // Plain object with capitalized / mixed-case headers
      const plainReqXFF = {
        headers: {
          'X-Forwarded-For': '198.51.100.33, 10.0.0.1'
        }
      };
      assert.equal(extractNextClientIp(plainReqXFF, true, 'x-forwarded-for'), '198.51.100.33');

      const plainReqRealIp = {
        headers: {
          'X-Real-IP': '198.51.100.34'
        }
      };
      assert.equal(extractNextClientIp(plainReqRealIp, true, 'nginx'), '198.51.100.34');

      const plainReqCF = {
        headers: {
          'CF-Connecting-IP': '198.51.100.35'
        }
      };
      assert.equal(extractNextClientIp(plainReqCF, true, 'cloudflare'), '198.51.100.35');

      const plainReqTrueClient = {
        headers: {
          'True-Client-IP': '198.51.100.36'
        }
      };
      assert.equal(extractNextClientIp(plainReqTrueClient, true, 'akamai'), '198.51.100.36');
    });
  });

  describe('Route Exclusion', () => {
    test('bypasses rate limiting for excluded routes', async () => {
      const shield = trackShield(createNextShield({
        mode: 'protect',
        maxRequests: 2,
        excludeRoutes: ['/api/health', '/api/public'],
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir
      }));

      const handler = shield.protect(async () => {
        return Response.json({ status: 'healthy' });
      });

      // 5 consecutive requests to excluded route
      for (let i = 0; i < 5; i++) {
        const req = new Request('http://localhost/api/health?query=check', {
          headers: { 'x-forwarded-for': '198.51.100.30' }
        });
        const res = await handler(req);
        assert.equal(res.status, 200);
        // Excluded routes do not receive rate limit headers
        assert.equal(res.headers.has('X-RateLimit-Limit'), false);
      }
    });
  });

  describe('Protection Mode (Rate Limiting & Blocking)', () => {
    test('enforces rate limit and returns HTTP 429 when threshold exceeded', async () => {
      const shield = trackShield(createNextShield({
        mode: 'protect',
        maxRequests: 2,
        windowMs: 60000,
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir
      }));

      const handler = shield.protect(async () => {
        return Response.json({ ok: true });
      });

      const req1 = new Request('http://localhost/api/data', {
        headers: { 'x-forwarded-for': '203.0.113.101' }
      });
      const res1 = await handler(req1);
      assert.equal(res1.status, 200);
      assert.equal(res1.headers.get('X-RateLimit-Remaining'), '1');
      assert.equal(res1.headers.get('X-Z-Shield-Protected'), '1');
      assert.equal(res1.headers.get('X-Z-Shield-Mode'), 'protect');

      const req2 = new Request('http://localhost/api/data', {
        headers: { 'x-forwarded-for': '203.0.113.101' }
      });
      const res2 = await handler(req2);
      assert.equal(res2.status, 200);
      assert.equal(res2.headers.get('X-RateLimit-Remaining'), '0');

      // 3rd request exceeds limit
      const req3 = new Request('http://localhost/api/data', {
        headers: { 'x-forwarded-for': '203.0.113.101' }
      });
      const res3 = await handler(req3);
      assert.equal(res3.status, 429);
      assert.equal(res3.headers.get('X-Z-Shield-Blocked'), '1');
      assert.ok(res3.headers.has('Retry-After'));

      const data = await res3.json();
      assert.equal(data.error, 'Too Many Requests');
      assert.ok(typeof data.retryAfter === 'number');
    });

    test('blocks pre-blocked IP immediately with 429', async () => {
      const shield = trackShield(createNextShield({
        mode: 'protect',
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir
      }));

      shield.block('198.51.100.99', '10m', 'Administrative ban');

      const handler = shield.protect(async () => {
        return Response.json({ allowed: true });
      });

      const req = new Request('http://localhost/api/secure', {
        headers: { 'x-forwarded-for': '198.51.100.99' }
      });
      const res = await handler(req);
      assert.equal(res.status, 429);
      assert.equal(res.headers.get('X-Z-Shield-Blocked'), '1');
      assert.equal(res.headers.get('X-Z-Shield-Reason'), 'Administrative ban');

      const body = await res.json();
      assert.equal(body.error, 'Too Many Requests');
      assert.equal(body.message, 'Your IP address has been temporarily blocked due to suspicious activity.');
    });

    test('autoBlock automatically blocks IP upon rate limit violation', async () => {
      const shield = trackShield(createNextShield({
        mode: 'protect',
        maxRequests: 1,
        autoBlock: true,
        blockDurationMs: 60000,
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir
      }));

      const handler = shield.protect(async () => Response.json({ ok: true }));

      const makeReq = () =>
        new Request('http://localhost/api/resource', {
          headers: { 'x-forwarded-for': '203.0.113.200' }
        });

      // Request 1: Allowed
      const res1 = await handler(makeReq());
      assert.equal(res1.status, 200);

      // Request 2: Exceeds rate limit -> triggers autoBlock
      const res2 = await handler(makeReq());
      assert.equal(res2.status, 429);

      // Verify IP is now in BlockManager
      assert.equal(shield.isBlocked('203.0.113.200'), true);
      const blockInfo = shield.getBlockInfo('203.0.113.200');
      assert.ok(blockInfo);

      // Request 3: Blocked by BlockManager
      const res3 = await handler(makeReq());
      assert.equal(res3.status, 429);
      assert.equal(res3.headers.get('X-Z-Shield-Blocked'), '1');

      // Unblock and verify restored access
      assert.equal(shield.unblock('203.0.113.200'), true);
      assert.equal(shield.isBlocked('203.0.113.200'), false);
    });
  });

  describe('Monitor Mode', () => {
    test('tracks requests and logs warnings without blocking in monitor mode', async () => {
      const shield = trackShield(createNextShield({
        mode: 'monitor',
        maxRequests: 1,
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir
      }));

      const handler = shield.protect(async () => {
        return Response.json({ message: 'monitoring' });
      });

      const makeReq = () =>
        new Request('http://localhost/api/test', {
          headers: { 'x-forwarded-for': '198.51.100.5' }
        });

      const res1 = await handler(makeReq());
      assert.equal(res1.status, 200);
      assert.equal(res1.headers.get('X-Z-Shield-Mode'), 'monitor');

      // 2nd request exceeds threshold but passes through in monitor mode
      const res2 = await handler(makeReq());
      assert.equal(res2.status, 200);
      assert.equal(res2.headers.get('X-Z-Shield-Suspicious'), '1');
      assert.equal(res2.headers.get('X-RateLimit-Remaining'), '0');

      const body = await res2.json();
      assert.equal(body.message, 'monitoring');
    });
  });

  describe('Response Handling & Special Status Codes', () => {
    test('handles 204 No Content responses safely without body error', async () => {
      const shield = trackShield(createNextShield({
        mode: 'protect',
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir
      }));

      const handler = shield.protect(async () => {
        return new Response(null, { status: 204 });
      });

      const req = new Request('http://localhost/api/delete', {
        headers: { 'x-forwarded-for': '198.51.100.7' }
      });
      const res = await handler(req);
      assert.equal(res.status, 204);
      assert.equal(res.headers.get('X-Z-Shield-Protected'), '1');
    });

    test('handles 205, 304, and 101 responses safely without body error when merging headers', async () => {
      const shield = trackShield(createNextShield({
        mode: 'protect',
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir
      }));

      // Test 304 Not Modified
      const handler304 = shield.protect(async () => new Response(null, { status: 304 }));
      const res304 = await handler304(new Request('http://localhost/api/test', {
        headers: { 'x-forwarded-for': '198.51.100.8' }
      }));
      assert.equal(res304.status, 304);
      assert.equal(res304.headers.get('X-Z-Shield-Protected'), '1');

      // Test 205 Reset Content
      const handler205 = shield.protect(async () => new Response(null, { status: 205 }));
      const res205 = await handler205(new Request('http://localhost/api/test', {
        headers: { 'x-forwarded-for': '198.51.100.9' }
      }));
      assert.equal(res205.status, 205);
      assert.equal(res205.headers.get('X-Z-Shield-Protected'), '1');
    });

    test('supports custom 429 block response builder', async () => {
      const shield = trackShield(createNextShield({
        mode: 'protect',
        maxRequests: 1,
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir,
        customBlockResponse: ({ reason, retryAfter }) => {
          return new Response(
            JSON.stringify({ customError: true, reason, wait: retryAfter }),
            { status: 429, headers: { 'Content-Type': 'application/json' } }
          );
        }
      }));

      const handler = shield.protect(async () => Response.json({ ok: true }));

      const makeReq = () =>
        new Request('http://localhost/api/custom', {
          headers: { 'x-forwarded-for': '198.51.100.88' }
        });

      await handler(makeReq());
      const blockedRes = await handler(makeReq());

      assert.equal(blockedRes.status, 429);
      const data = await blockedRes.json();
      assert.equal(data.customError, true);
      assert.ok(typeof data.wait === 'number');
    });
  });

  describe('Wrapper Functions & Context Passing', () => {
    test('withNextShield wraps handler and passes route context parameter', async () => {
      let receivedParams = null;

      const shield = trackShield(createNextShield({
        mode: 'protect',
        maxRequests: 10,
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir
      }));
      const handler = withNextShield(
        async (req, context) => {
          receivedParams = context?.params;
          return Response.json({ id: context?.params?.id });
        },
        shield
      );

      const req = new Request('http://localhost/api/items/42', {
        headers: { 'x-forwarded-for': '198.51.100.12' }
      });

      const res = await handler(req, { params: { id: '42' } });
      assert.equal(res.status, 200);
      assert.deepEqual(receivedParams, { id: '42' });

      const data = await res.json();
      assert.equal(data.id, '42');
    });

    test('can reuse core instances from an existing ZShieldInstance with adapterOptions', async () => {
      // Create standard shield instance (e.g. for Express or shared state)
      const coreShield = trackShield(createShield({
        mode: 'protect',
        maxRequests: 3,
        logDir: tempLogDir,
        trustProxy: true
      }));

      // Wrap with Next.js adapter reusing the same core instance and specifying getIp strategy
      const nextShield = trackShield(createNextShield(coreShield, { getIp: 'x-forwarded-for' }));

      // Block IP on core instance
      coreShield.block('198.51.100.55', '10m', 'Cross-adapter block');

      // Next.js adapter should immediately reflect the block
      assert.equal(nextShield.isBlocked('198.51.100.55'), true);

      const handler = nextShield.protect(async () => Response.json({ ok: true }));
      const req = new Request('http://localhost/api/test', {
        headers: { 'x-forwarded-for': '198.51.100.55' }
      });
      const res = await handler(req);
      assert.equal(res.status, 429);
    });
  });

  describe('Persistent Logging', () => {
    test('logs rate limit and block security events to JSONL', async () => {
      const shield = trackShield(createNextShield({
        mode: 'protect',
        maxRequests: 1,
        trustProxy: true,
        getIp: 'x-forwarded-for',
        logDir: tempLogDir,
        appName: 'nextjs-test-app'
      }));

      const handler = shield.protect(async () => Response.json({ ok: true }));

      const req = new Request('http://localhost/api/resource', {
        headers: { 'x-forwarded-for': '203.0.113.77' }
      });

      // 1st: allowed
      await handler(req);
      // 2nd: rate limit block
      await handler(req);

      await shield.flush();

      const logFile = path.join(tempLogDir, 'events.jsonl');
      assert.equal(fs.existsSync(logFile), true);

      const logContent = fs.readFileSync(logFile, 'utf8').trim();
      const lines = logContent.split('\n');
      assert.ok(lines.length >= 1);

      const event = JSON.parse(lines[0]);
      assert.equal(event.appName, 'nextjs-test-app');
      assert.equal(event.ip, '203.0.113.77');
      assert.equal(event.type, 'rate_limit');
    });

    test('route handler safely treats IP as unknown and avoids spoofing when trustProxy is true without getIp strategy', async () => {
      const shield = trackShield(createNextShield({
        mode: 'protect',
        maxRequests: 2,
        trustProxy: true,
        // deliberately omit getIp strategy
        logDir: tempLogDir,
        appName: 'safe-fallback-app'
      }));

      const handler = shield.protect(async () => Response.json({ ok: true }));

      // Attacker tries sending forged X-Forwarded-For header
      const req = new Request('http://localhost/api/test', {
        headers: { 'x-forwarded-for': '198.51.100.88' }
      });

      const res = await handler(req);
      assert.equal(res.status, 200);

      // Verify that the event logged had IP 'unknown' rather than the untrusted forged IP
      await shield.flush();
      const logFile = path.join(tempLogDir, 'events.jsonl');
      // No block event was generated for the 1st request, but check detection IP via check() API
      const checkResult = await shield.check(req);
      assert.equal(checkResult.clientIp, 'unknown');
    });
  });
});

