import assert from 'node:assert/strict';
import test from 'node:test';

// One module instance per index: each keeps its index in a module-level cache.
// This relies on Node's ES module loader treating each query string as a
// separate module (as `node --test` does); a runner or bundler that drops the
// query would share one cache between these tests and break them.
import { onRequest as searchCasedIndex } from '../functions/search.js?platform-cased';
import { onRequest as searchClashIndex } from '../functions/search.js?platform-clash';
import { onRequest as searchLegacyIndex } from '../functions/search.js?platform-legacy';
import { onRequest as searchNoPlatformsIndex } from '../functions/search.js?platform-defaults';

function indexWith(platforms) {
  const lookups = { as_names: {}, country_names: {}, flags: ['exit'], validated_aroi_domains: [] };
  if (platforms) lookups.platforms = platforms;
  return { meta: { version: '1.7' }, relays: [], families: [], lookups };
}

async function redirectPath(handler, index, q) {
  const env = {
    ALLIUM_ASSETS: {
      async fetch(request) {
        assert.equal(new URL(request.url).pathname, '/search-index.json');
        return Response.json(index);
      },
    },
  };
  const response = await handler({
    request: new Request(`https://metrics.example/search?q=${encodeURIComponent(q)}`),
    env,
  });
  assert.equal(response.status, 302);
  return new URL(response.headers.get('location')).pathname;
}

test('platform search redirects to the page folder in its own case', async () => {
  const index = indexWith(['FreeBSD', 'Linux', 'Linux-libre', 'Windows']);
  assert.equal(await redirectPath(searchCasedIndex, index, 'freebsd'), '/platform/FreeBSD/');
  assert.equal(await redirectPath(searchCasedIndex, index, 'FREEBSD'), '/platform/FreeBSD/');
  assert.equal(await redirectPath(searchCasedIndex, index, 'linux'), '/platform/Linux/');
  assert.equal(await redirectPath(searchCasedIndex, index, 'Linux-Libre'), '/platform/Linux-libre/');
});

test('the first spelling of a platform wins a case clash', async () => {
  const index = indexWith(['Linux', 'linux']);
  assert.equal(await redirectPath(searchClashIndex, index, 'linux'), '/platform/Linux/');
});

test('all-lowercase platforms from older indexes redirect as before', async () => {
  const index = indexWith(['linux']);
  assert.equal(await redirectPath(searchLegacyIndex, index, 'Linux'), '/platform/linux/');
});

test('an index without platforms falls back to the usual page folders', async () => {
  const index = indexWith(undefined);
  assert.equal(await redirectPath(searchNoPlatformsIndex, index, 'freebsd'), '/platform/FreeBSD/');
  assert.equal(await redirectPath(searchNoPlatformsIndex, index, 'linux'), '/platform/Linux/');
});
