import assert from 'node:assert/strict';
import test from 'node:test';

import { onRequest } from '../functions/[[path]].js';

test('direct Pages reads and production purges share the canonical cache key', async () => {
  const originalCaches = globalThis.caches;
  const originalFetch = globalThis.fetch;
  const matched = [];
  const stored = [];
  const deleted = [];

  globalThis.caches = {
    default: {
      async match(request) {
        matched.push(request.url);
        return undefined;
      },
      async put(request) {
        stored.push(request.url);
      },
      async delete(request) {
        deleted.push(request.url);
        return true;
      },
    },
  };
  globalThis.fetch = async () => new Response('<html>current</html>', { status: 200 });

  const env = {
    CACHE_KEY_ORIGIN: 'https://metrics.1aeo.com',
    CACHE_TTL_HTML: '1800',
    STORAGE_ORDER: 'do',
    DO_SPACES_URL: 'https://spaces.example',
    PURGE_SECRET: 'test-secret',
  };

  try {
    const directResponse = await onRequest({
      request: new Request('https://1aeo-metrics.pages.dev/relay/abc/'),
      env,
      params: { path: ['relay', 'abc', ''] },
      waitUntil(promise) { return promise; },
    });
    assert.equal(directResponse.status, 200);
    assert.deepEqual(matched, ['https://metrics.1aeo.com/relay/abc/']);
    assert.deepEqual(stored, ['https://metrics.1aeo.com/relay/abc/']);

    const purgeResponse = await onRequest({
      request: new Request('https://1aeo-metrics.pages.dev/_purge', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Purge-Secret': 'test-secret',
        },
        body: JSON.stringify({ urls: ['https://metrics.1aeo.com/relay/abc/'] }),
      }),
      env,
      params: { path: ['_purge'] },
      waitUntil() {},
    });
    assert.equal(purgeResponse.status, 200);
    assert.deepEqual(await purgeResponse.json(), {
      success: true,
      purged: 1,
      requested: 1,
    });
    assert.deepEqual(deleted, ['https://metrics.1aeo.com/relay/abc/']);
  } finally {
    globalThis.caches = originalCaches;
    globalThis.fetch = originalFetch;
  }
});

test('malformed optional canonical origin falls back to the request origin', async () => {
  const originalCaches = globalThis.caches;
  const matched = [];
  globalThis.caches = {
    default: {
      async match(request) {
        matched.push(request.url);
        return new Response('cached');
      },
      async put() {},
      async delete() { return false; },
    },
  };

  try {
    const response = await onRequest({
      request: new Request('https://1aeo-metrics.pages.dev/index.html'),
      env: { CACHE_KEY_ORIGIN: 'not a URL' },
      params: { path: ['index.html'] },
      waitUntil() {},
    });
    assert.equal(response.status, 200);
    assert.deepEqual(matched, ['https://1aeo-metrics.pages.dev/index.html']);
  } finally {
    globalThis.caches = originalCaches;
  }
});
