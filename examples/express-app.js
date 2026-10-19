'use strict';

/**
 * Z-Shield Demo Express Application
 *
 * This runnable example demonstrates how a developer mounts Z-Shield
 * into an existing Express application.
 */

const express = require('express');
const { createShield } = require('../src/index');

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Initialize Z-Shield
// In Phase 2, we use a small maxRequests (5) so you can easily test
// hitting the threshold in your terminal!
const shield = createShield({
  appName: 'demo-api',
  mode: 'monitor',
  windowMs: 30 * 1000, // 30 second window
  maxRequests: 5,      // 5 requests per 30 seconds
  maxTrackedIps: 1000, // Memory cap
  trustProxy: false,   // Set to true only if behind a reverse proxy like Nginx
  excludeRoutes: ['/health']
});

// 2. Register Z-Shield middleware as early as possible in your middleware pipeline
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

// Excluded health check route
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
    console.log(`====================================================`);
    console.log(`Try running these commands in another terminal:`);
    console.log(`  curl -i http://localhost:${PORT}/`);
    console.log(`  curl -i http://localhost:${PORT}/health`);
    console.log(`====================================================`);
  });
}

module.exports = app;
