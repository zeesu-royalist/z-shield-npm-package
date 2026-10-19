'use strict';

/**
 * Z-Shield Demo Express Application
 *
 * Demonstrates:
 * 1. Monitor Mode vs Protect Mode (toggle via SHIELD_MODE environment variable)
 * 2. Rate limit enforcement returning HTTP 429
 * 3. Retry-After headers
 */

const express = require('express');
const { createShield } = require('../src/index');

const app = express();
const PORT = process.env.PORT || 3000;

// Determine mode: default to 'protect' for Phase 3 testing, or 'monitor' if specified
const currentMode = process.env.SHIELD_MODE === 'monitor' ? 'monitor' : 'protect';

// 1. Initialize Z-Shield
const shield = createShield({
  appName: 'demo-api',
  mode: currentMode,
  windowMs: 30 * 1000, // 30 second window
  maxRequests: 5,      // 5 requests per 30 seconds
  blockDurationMs: 60 * 1000, // 1 minute block duration
  maxTrackedIps: 1000,
  trustProxy: false,
  excludeRoutes: ['/health']
});

// 2. Register Z-Shield middleware
app.use(shield.middleware);

// 3. Define sample application routes
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    message: 'Welcome to the Z-Shield protected API!',
    zShieldContext: req.zShield
  });
});

app.get('/api/users', (req, res) => {
  res.json({
    users: [
      { id: 1, name: 'Alice' },
      { id: 2, name: 'Bob' }
    ]
  });
});

// Excluded health check route (never blocked)
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// 4. Start the server (only if executed directly from terminal)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`🛡️  Z-Shield Demo Server running at http://localhost:${PORT}`);
    console.log(`Mode: ${shield.config.mode.toUpperCase()}`);
    console.log(`Limit: ${shield.config.maxRequests} requests per ${shield.config.windowMs / 1000}s`);
    console.log(`Log File: ${shield.logger.filePath}`);
    console.log(`====================================================`);
    console.log(`To test Protect Mode (returns HTTP 429 after 5 requests):`);
    console.log(`  for i in {1..6}; do curl -s -i http://localhost:${PORT}/ | head -n 8; echo "---"; done`);
    console.log(`====================================================`);
    console.log(`To view logged security events in your terminal:`);
    console.log(`  cat .z-shield-logs/events.jsonl`);
    console.log(`====================================================`);
  });
}

module.exports = app;
