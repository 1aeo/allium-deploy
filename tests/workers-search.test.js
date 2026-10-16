import assert from 'node:assert/strict';
import test from 'node:test';

import worker from '../workers/search.js';
import { onRequest as handlePagesSearch } from '../functions/search.js?pages-assets-collision-regression';

const fingerprint = 'A'.repeat(40);
const searchIndex = {
  meta: { version: '1.6' },
  relays: [{ f: fingerprint, n: 'TestRelay', cc: 'US' }],
  families: [],
  lookups: {
    as_names: {},
    country_names: { us: 'United States' },
    platforms: ['linux'],
    flags: ['running'],
    validated_aroi_domains: [],
  },
};

function executionContext() {
  return {
    waitUntil() {},
    passThroughOnException() {},
  };
}

test('Pages built-in ASSETS binding is not mistaken for Allium content', async () => {
  const originalFetch = globalThis.fetch;
  let pagesAssetsCalls = 0;

  globalThis.fetch = async (request) => {
    assert.equal(new URL(request.url).pathname, '/search-index.json');
    return Response.json(searchIndex);
  };

  try {
    const response = await handlePagesSearch({
      request: new Request(`https://metrics.example/search?q=${fingerprint}`),
      env: {
        ASSETS: {
          async fetch() {
            pagesAssetsCalls += 1;
            return new Response('Pages static bundle has no index', { status: 404 });
          },
        },
      },
    });

    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), `https://metrics.example/relay/${fingerprint}/`);
    assert.equal(pagesAssetsCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Workers search reads the version-matched ALLIUM_ASSETS binding', async () => {
  const fetched = [];
  const env = {
    ALLIUM_ASSETS: {
      async fetch(request) {
        const url = new URL(request.url);
        fetched.push(url.pathname);
        if (url.pathname === '/search-index.json') {
          return Response.json(searchIndex);
        }
        return new Response('not found', { status: 404 });
      },
    },
  };

  const response = await worker.fetch(
    new Request(`https://preview.example/search?q=${fingerprint}`),
    env,
    executionContext(),
  );

  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), `https://preview.example/relay/${fingerprint}/`);
  assert.deepEqual(fetched, ['/search-index.json']);
});

test('rehearsal search responses are noindex without affecting production', async () => {
  const env = {
    ALLIUM_ASSETS: {
      async fetch(request) {
        if (new URL(request.url).pathname === '/search-index.json') {
          return Response.json(searchIndex);
        }
        return new Response('not found', { status: 404 });
      },
    },
  };

  const rehearsal = await worker.fetch(
    new Request(`https://metrics-next.1aeo.com/search?q=${fingerprint}`),
    env,
    executionContext(),
  );
  assert.equal(rehearsal.status, 302);
  assert.equal(rehearsal.headers.get('x-robots-tag'), 'noindex, nofollow');

  const preview = await worker.fetch(
    new Request(`https://candidate.example.workers.dev/search?q=${fingerprint}`),
    env,
    executionContext(),
  );
  assert.equal(preview.headers.get('x-robots-tag'), 'noindex, nofollow');

  const production = await worker.fetch(
    new Request(`https://metrics.1aeo.com/search?q=${fingerprint}`),
    env,
    executionContext(),
  );
  assert.equal(production.status, 302);
  assert.equal(production.headers.get('x-robots-tag'), null);
});

test('non-search Worker invocations delegate to static asset behavior', async () => {
  let delegatedPath = '';
  const env = {
    ALLIUM_ASSETS: {
      async fetch(request) {
        delegatedPath = new URL(request.url).pathname;
        return new Response('static 404', { status: 404 });
      },
    },
  };

  const response = await worker.fetch(
    new Request('https://preview.example/missing-object'),
    env,
    executionContext(),
  );

  assert.equal(response.status, 404);
  assert.equal(await response.text(), 'static 404');
  assert.equal(delegatedPath, '/missing-object');
});
