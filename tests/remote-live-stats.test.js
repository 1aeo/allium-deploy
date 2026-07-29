import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { measureRemoteLiveStats } from '../scripts/audit-remote-live-stats.js';

async function fixture(t) {
  const source = await fs.mkdtemp(path.join(os.tmpdir(), 'allium-live-stats-'));
  t.after(() => fs.rm(source, { recursive: true, force: true }));
  await fs.mkdir(path.join(source, 'alpha'));
  await fs.mkdir(path.join(source, 'beta'));
  await fs.writeFile(path.join(source, 'index.html'), 'hello');
  await fs.writeFile(path.join(source, '_headers'), 'worker-only');
  return source;
}

function runner({ extraDirectory = false, rootSize = 5 } = {}) {
  return async (_rclone, args) => {
    if (args[0] === 'lsjson') {
      return JSON.stringify([
        { Path: '_backups', IsDir: true, Size: -1 },
        { Path: 'alpha', IsDir: true, Size: -1 },
        { Path: 'beta', IsDir: true, Size: -1 },
        ...(extraDirectory ? [{ Path: 'stale', IsDir: true, Size: -1 }] : []),
        { Path: 'index.html', IsDir: false, Size: rootSize },
      ]);
    }
    if (args[0] === 'size' && args[1].endsWith('/alpha')) {
      return JSON.stringify({ count: 2, bytes: 10, sizeless: 0 });
    }
    if (args[0] === 'size' && args[1].endsWith('/beta')) {
      return JSON.stringify({ count: 1, bytes: 7, sizeless: 0 });
    }
    throw new Error(`unexpected rclone arguments: ${args.join(' ')}`);
  };
}

test('measures only live prefixes while excluding the backup tree and Worker header', async (t) => {
  const source = await fixture(t);
  const stats = await measureRemoteLiveStats({
    source,
    remote: 'fake:bucket',
    concurrency: 2,
    runRclone: runner(),
  });
  assert.deepEqual(stats, { count: 4, bytes: 22 });
});

test('rejects an extra remote live directory', async (t) => {
  const source = await fixture(t);
  await assert.rejects(
    measureRemoteLiveStats({
      source,
      remote: 'fake:bucket',
      runRclone: runner({ extraDirectory: true }),
    }),
    /live root directories differ.*stale/,
  );
});

test('rejects a root-file size mismatch', async (t) => {
  const source = await fixture(t);
  await assert.rejects(
    measureRemoteLiveStats({
      source,
      remote: 'fake:bucket',
      runRclone: runner({ rootSize: 6 }),
    }),
    /root file size differs: index.html/,
  );
});

test('rejects unsafe concurrency', async (t) => {
  const source = await fixture(t);
  await assert.rejects(
    measureRemoteLiveStats({ source, remote: 'fake:bucket', concurrency: 0, runRclone: runner() }),
    /concurrency must be an integer/,
  );
});
