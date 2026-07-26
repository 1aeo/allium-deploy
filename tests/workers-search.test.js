import assert from 'node:assert/strict';
import test from 'node:test';

import worker from '../workers/search.js';

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

test('Workers search reads the version-matched ASSETS binding', async () => {
  const fetched = [];
  const env = {
    ASSETS: {
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

test('non-search Worker invocations delegate to static asset behavior', async () => {
  let delegatedPath = '';
  const env = {
    ASSETS: {
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
