import assert from 'node:assert/strict';
import test from 'node:test';

import { onRequest } from '../functions/[[path]].js';

globalThis.caches = {
  default: {
    async match() { return undefined; },
    async put() {},
    async delete() { return false; },
  },
};

function requestFor(path) {
  const request = new Request(`https://metrics.example/${path}`);
  Object.defineProperty(request, 'cf', { value: { colo: 'TEST' } });
  return request;
}

function telemetryEnv(extra = {}) {
  const points = [];
  return {
    points,
    env: {
      CACHE_TTL_HTML: '1800',
      CACHE_TTL_STATIC: '86400',
      SOURCE_EVENTS: {
        writeDataPoint(point) { points.push(point); },
      },
      ...extra,
    },
  };
}

async function invoke(path, env) {
  return onRequest({
    request: requestFor(path),
    env,
    params: { path: path.split('/') },
    waitUntil() {},
  });
}

test('an R2 response records one bounded source event', async () => {
  const { env, points } = telemetryEnv({
    STORAGE_ORDER: 'r2',
    METRICS_CONTENT: {
      async get(path) {
        return path === 'status.json' ? { body: '{"ok":true}' } : null;
      },
    },
  });

  const response = await invoke('status.json', env);
  assert.equal(response.status, 200);
  assert.equal(points.length, 1);
  assert.deepEqual(points[0], {
    indexes: ['allium-source'],
    blobs: ['cloudflare-r2', 'served', 'json', 'TEST'],
    doubles: [1],
  });
});

test('the normal DigitalOcean source writes no telemetry point', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('<html>ok</html>', { status: 200 });

  try {
    const { env, points } = telemetryEnv({
      STORAGE_ORDER: 'do',
      DO_SPACES_URL: 'https://spaces.example',
    });
    const response = await invoke('index.html', env);
    assert.equal(response.status, 200);
    assert.equal(points.length, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('all source failure records one event without URL or client data', async () => {
  const { env, points } = telemetryEnv({ STORAGE_ORDER: '' });
  const response = await invoke('private/path', env);

  assert.equal(response.status, 404);
  assert.equal(points.length, 1);
  assert.deepEqual(points[0], {
    indexes: ['allium-source'],
    blobs: ['none', 'all-sources-failed', 'other', 'TEST'],
    doubles: [1],
  });
  assert.equal(JSON.stringify(points[0]).includes('private/path'), false);
});

test('telemetry binding failure cannot affect content delivery', async () => {
  const env = {
    STORAGE_ORDER: 'r2',
    METRICS_CONTENT: {
      async get() { return { body: 'ok' }; },
    },
    SOURCE_EVENTS: {
      writeDataPoint() { throw new Error('analytics unavailable'); },
    },
  };

  const response = await invoke('index.html', env);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'ok');
});
