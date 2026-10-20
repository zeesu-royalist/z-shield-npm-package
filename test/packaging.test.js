'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const cp = require('node:child_process');

describe('npm Package & Distribution Verification', () => {
  let packDest;
  let tempConsumerDir;
  let tarballPath;
  const projectRoot = path.resolve(__dirname, '..');
  
  let tscBin;
  try {
    tscBin = require.resolve('typescript/bin/tsc');
  } catch {
    tscBin = path.join(projectRoot, 'node_modules', 'typescript', 'bin', 'tsc');
  }

  before(() => {
    // 1. Pack the package to a dedicated temporary directory
    packDest = fs.mkdtempSync(path.join(os.tmpdir(), 'z-shield-pack-'));
    cp.execSync(`npm pack --pack-destination "${packDest}"`, {
      cwd: projectRoot,
      encoding: 'utf8',
      stdio: 'pipe'
    });

    const tarballs = fs.readdirSync(packDest).filter((f) => f.endsWith('.tgz'));
    assert.ok(tarballs.length > 0, `No tarball generated in ${packDest}`);
    tarballPath = path.join(packDest, tarballs[0]);
    assert.ok(fs.existsSync(tarballPath), `Tarball not found at ${tarballPath}`);

    // 2. Create isolated consumer project
    tempConsumerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-shield-consumer-'));
    fs.writeFileSync(
      path.join(tempConsumerDir, 'package.json'),
      JSON.stringify({
        name: 'test-consumer-app',
        version: '1.0.0',
        dependencies: {
          'z-shield': `file:${tarballPath}`
        }
      })
    );

    // 3. Install into consumer using local tarball (offline-safe, no audit/fund)
    cp.execSync('npm install --no-audit --no-fund --prefer-offline', {
      cwd: tempConsumerDir,
      stdio: 'pipe'
    });
  });

  after(() => {
    if (tempConsumerDir && fs.existsSync(tempConsumerDir)) {
      try {
        fs.rmSync(tempConsumerDir, { recursive: true, force: true });
      } catch {}
    }
    if (packDest && fs.existsSync(packDest)) {
      try {
        fs.rmSync(packDest, { recursive: true, force: true });
      } catch {}
    }
  });

  test('resolves main CommonJS entry and exports package.json', () => {
    const testScript = `
      const assert = require('assert');
      const { createShield, BlockManager, RateLimiter, normalizeIp } = require('z-shield');
      const pkg = require('z-shield/package.json');

      assert.equal(typeof createShield, 'function');
      assert.equal(typeof BlockManager, 'function');
      assert.equal(typeof RateLimiter, 'function');
      assert.equal(normalizeIp('::1'), '127.0.0.1');
      assert.equal(pkg.name, 'z-shield');
      assert.equal(typeof pkg.version, 'string');
    `;
    const scriptPath = path.join(tempConsumerDir, 'test-cjs-main.js');
    fs.writeFileSync(scriptPath, testScript);
    cp.execSync(`node "${scriptPath}"`, { cwd: tempConsumerDir, stdio: 'pipe' });
  });

  test('resolves ./next subpath in CommonJS consumer', () => {
    const testScript = `
      const assert = require('assert');
      const { createNextShield, withNextShield, extractNextClientIp } = require('z-shield/next');

      assert.equal(typeof createNextShield, 'function');
      assert.equal(typeof withNextShield, 'function');
      assert.equal(typeof extractNextClientIp, 'function');
    `;
    const scriptPath = path.join(tempConsumerDir, 'test-cjs-next.js');
    fs.writeFileSync(scriptPath, testScript);
    cp.execSync(`node "${scriptPath}"`, { cwd: tempConsumerDir, stdio: 'pipe' });
  });

  test('resolves main and ./next entries in ESM consumer', () => {
    const esmScript = `
      import assert from 'node:assert';
      import { createShield, BlockManager, RateLimiter } from 'z-shield';
      import { createNextShield, withNextShield } from 'z-shield/next';

      assert.equal(typeof createShield, 'function');
      assert.equal(typeof BlockManager, 'function');
      assert.equal(typeof RateLimiter, 'function');
      assert.equal(typeof createNextShield, 'function');
      assert.equal(typeof withNextShield, 'function');
    `;
    const scriptPath = path.join(tempConsumerDir, 'test-esm.mjs');
    fs.writeFileSync(scriptPath, esmScript);
    cp.execSync(`node "${scriptPath}"`, { cwd: tempConsumerDir, stdio: 'pipe' });
  });

  test('executes CLI binary via local bin link and npx in consumer', () => {
    // 1. Verify installed binary in node_modules/.bin
    const binPath = path.join(tempConsumerDir, 'node_modules', '.bin', 'z-shield');
    assert.ok(fs.existsSync(binPath), `CLI binary symlink not found at ${binPath}`);

    // 2. Execute via npx with --no-install to guarantee local execution without registry lookup
    const output = cp.execSync('npx --no-install z-shield --help', {
      cwd: tempConsumerDir,
      encoding: 'utf8'
    });
    assert.ok(output.includes('Z-Shield CLI'));
    assert.ok(output.includes('status'));
    assert.ok(output.includes('logs'));
    assert.ok(output.includes('monitor'));
  });

  test('compiles TypeScript consumer across node16 and bundler module resolutions', () => {
    const tsConsumerCode = `
      import { createShield, type ZShieldConfig, type BlockRecord } from 'z-shield';
      import { createNextShield, withNextShield, type NextShieldInstance, type NextShieldOptions } from 'z-shield/next';

      const shield = createShield({ mode: 'protect', maxRequests: 50 });
      const block: BlockRecord = shield.block('198.51.100.1', '10m');
      const nextShield: NextShieldInstance = createNextShield({ mode: 'protect' });
      if (block.ip !== '198.51.100.1') {
        throw new Error('IP mismatch');
      }
    `;
    const tsFile = path.join(tempConsumerDir, 'consumer.ts');
    fs.writeFileSync(tsFile, tsConsumerCode);

    const tsConfigPath = path.join(tempConsumerDir, 'tsconfig.json');

    // 1. Compile with node16 module resolution
    fs.writeFileSync(
      tsConfigPath,
      JSON.stringify({
        compilerOptions: {
          target: 'es2022',
          module: 'node16',
          moduleResolution: 'node16',
          noEmit: true,
          skipLibCheck: true
        },
        include: ['consumer.ts']
      })
    );
    cp.execSync(`node "${tscBin}" -p .`, {
      cwd: tempConsumerDir,
      stdio: 'pipe'
    });

    // 2. Compile with bundler module resolution
    fs.writeFileSync(
      tsConfigPath,
      JSON.stringify({
        compilerOptions: {
          target: 'es2022',
          module: 'esnext',
          moduleResolution: 'bundler',
          noEmit: true,
          skipLibCheck: true
        },
        include: ['consumer.ts']
      })
    );
    cp.execSync(`node "${tscBin}" -p .`, {
      cwd: tempConsumerDir,
      stdio: 'pipe'
    });
  });
});
