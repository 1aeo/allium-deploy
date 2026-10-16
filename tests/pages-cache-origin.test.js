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
  const fetched = [];
  // DigitalOcean answers 403 for a missing key in this bucket.
  globalThis.fetch = async (url, init = {}) => {
    fetched.push(`${init.method || 'GET'} ${url}`);
    return url === 'https://spaces.example/relay/abc/index.html'
      ? new Response('<html>current</html>', { status: 200 })
      : new Response('AccessDenied', { status: 403 });
  };

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
      // Pages omits the trailing empty segment for folder URLs.
      params: { path: ['relay', 'abc'] },
      waitUntil(promise) { return promise; },
    });
    assert.equal(directResponse.status, 200);
    assert.equal(directResponse.headers.get('X-Served-From'), 'digitalocean-spaces');
    assert.deepEqual(fetched, ['GET https://spaces.example/relay/abc/index.html']);
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

test('extension-less pages share the cache key the purge sends for their .html file', async () => {
  const originalCaches = globalThis.caches;
  const originalFetch = globalThis.fetch;
  const matched = [];
  const stored = [];
  globalThis.caches = {
    default: {
      async match(request) {
        matched.push(request.url);
        return undefined;
      },
      async put(request) { stored.push(request.url); },
      async delete() { return false; },
    },
  };
  globalThis.fetch = async (url) => (url === 'https://spaces.example/misc/all.html'
    ? new Response('<html>all</html>', { status: 200 })
    : new Response('AccessDenied', { status: 403 }));

  try {
    const response = await onRequest({
      request: new Request('https://1aeo-metrics.pages.dev/misc/all'),
      env: {
        CACHE_KEY_ORIGIN: 'https://metrics.1aeo.com',
        STORAGE_ORDER: 'do',
        DO_SPACES_URL: 'https://spaces.example',
      },
      params: { path: ['misc', 'all'] },
      waitUntil(promise) { return promise; },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(matched, ['https://metrics.1aeo.com/misc/all.html']);
    assert.deepEqual(stored, ['https://metrics.1aeo.com/misc/all.html']);
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
