import assert from 'node:assert/strict';
import { afterEach, beforeEach, test } from 'node:test';

import { onRequest } from '../functions/[[path]].js';

const SPACES = 'https://spaces.example';
const FAILOVER = 'https://failover.example/mirror';

const OBJECTS = {
  'index.html': '<html>home</html>',
  'relay/ABC/index.html': '<html>relay</html>',
  '1aeo.com/index.html': '<html>aroi</html>',
  'misc/all.html': '<html>all</html>',
  'search-index.json': '{"meta":{}}',
  'static/css/allium-base.css': 'body{}',
  'static/images/flags/us.png': 'png',
  'metrics': 'allium_up 1',
};

let originalCaches;
let originalFetch;
let stored;

beforeEach(() => {
  originalCaches = globalThis.caches;
  originalFetch = globalThis.fetch;
  stored = [];
  globalThis.caches = {
    default: {
      async match() { return undefined; },
      async put(request) { stored.push(request.url); },
      async delete() { return false; },
    },
  };
});

afterEach(() => {
  globalThis.caches = originalCaches;
  globalThis.fetch = originalFetch;
});

// Records every origin request as "METHOD key". DigitalOcean answers 403
// for a missing key in this bucket; missingStatus overrides that.
function mockOrigins({ spaces = OBJECTS, failover = {}, spacesDown, missingStatus = 403 } = {}) {
  const requests = { do: [], failover: [] };
  const failoverBase = new URL(FAILOVER);
  globalThis.fetch = async (url, init = {}) => {
    const method = init.method || 'GET';
    // Read the key as the origin would: from the parsed path only, escapes
    // decoded. A path outside the failover prefix keeps its leading slash.
    const { origin: host, pathname } = new URL(url);
    const [origin, prefix, objects] = host === failoverBase.origin
      ? ['failover', `${failoverBase.pathname}/`, failover] : ['do', '/', spaces];
    const key = pathname.startsWith(prefix)
      ? decodeURIComponent(pathname.slice(prefix.length)) : pathname;
    requests[origin].push(`${method} ${key}`);
    if (origin === 'do' && spacesDown === 'network') throw new TypeError('fetch failed');
    if (origin === 'do' && spacesDown) return new Response('down', { status: spacesDown });
    if (!Object.hasOwn(objects, key)) return new Response('missing', { status: missingStatus });
    return new Response(method === 'HEAD' ? null : objects[key], { status: 200 });
  };
  return requests;
}

function mockR2(objects = OBJECTS) {
  const requests = [];
  return {
    requests,
    binding: {
      async get(key) {
        requests.push(`get ${key}`);
        return Object.hasOwn(objects, key) ? { body: objects[key] } : null;
      },
      async head(key) {
        requests.push(`head ${key}`);
        return Object.hasOwn(objects, key) ? {} : null;
      },
    },
  };
}

function invoke(path, env) {
  const url = new URL(`https://1aeo-metrics.pages.dev${path}`);
  // Pages passes folder URLs without the trailing empty segment.
  const segments = url.pathname.split('/').filter(Boolean);
  return onRequest({
    request: new Request(url),
    env,
    params: segments.length ? { path: segments } : {},
    waitUntil() {},
  });
}

function rollbackEnv(r2, extra = {}) {
  return {
    STORAGE_ORDER: 'do,r2,failover',
    DO_SPACES_URL: SPACES,
    METRICS_CONTENT: r2.binding,
    CACHE_KEY_ORIGIN: 'https://metrics.1aeo.com',
    ...extra,
  };
}

test('folder URLs read <dir>/index.html from DigitalOcean in one request', async () => {
  for (const [path, key, body] of [
    ['/relay/ABC/', 'relay/ABC/index.html', '<html>relay</html>'],
    ['/1aeo.com/', '1aeo.com/index.html', '<html>aroi</html>'],
    ['/', 'index.html', '<html>home</html>'],
  ]) {
    const origins = mockOrigins();
    const r2 = mockR2();
    const response = await invoke(path, rollbackEnv(r2));

    assert.equal(response.status, 200, path);
    assert.equal(await response.text(), body);
    assert.equal(response.headers.get('X-Served-From'), 'digitalocean-spaces');
    assert.equal(response.headers.get('Content-Type'), 'text/html; charset=utf-8');
    assert.deepEqual(origins.do, [`GET ${key}`], path);
    assert.deepEqual(r2.requests, [], path);
  }
});

test('extension-less page URLs read <page>.html first', async () => {
  const origins = mockOrigins();
  const r2 = mockR2();
  const response = await invoke('/misc/all', rollbackEnv(r2));

  assert.equal(response.status, 200);
  assert.equal(await response.text(), '<html>all</html>');
  assert.equal(response.headers.get('Content-Type'), 'text/html; charset=utf-8');
  assert.deepEqual(origins.do, ['GET misc/all.html']);
  assert.deepEqual(r2.requests, []);
});

test('slashless folder URLs redirect to the slash form like production', async () => {
  for (const [path, location, probes] of [
    ['/relay/ABC', '/relay/ABC/', ['GET relay/ABC.html', 'HEAD relay/ABC/index.html']],
    ['/relay/ABC?x=1', '/relay/ABC/?x=1', ['GET relay/ABC.html', 'HEAD relay/ABC/index.html']],
    ['/1aeo.com', '/1aeo.com/', ['GET 1aeo.com.html', 'HEAD 1aeo.com/index.html']],
    // Never a protocol-relative (off-site) Location.
    ['//1aeo.com', '/1aeo.com/', ['GET 1aeo.com.html', 'HEAD 1aeo.com/index.html']],
  ]) {
    const origins = mockOrigins();
    const r2 = mockR2();
    const response = await invoke(path, rollbackEnv(r2));

    assert.equal(response.status, 307, path);
    assert.equal(response.headers.get('Location'), location);
    assert.deepEqual(origins.do, probes, path);
    assert.deepEqual(r2.requests, [], path);
  }
  assert.deepEqual(stored, []);
});

test('DigitalOcean 404 is treated like its 403 for a missing key', async () => {
  const origins = mockOrigins({ missingStatus: 404 });
  const r2 = mockR2();
  const response = await invoke('/relay/ABC', rollbackEnv(r2));

  assert.equal(response.status, 307);
  assert.deepEqual(origins.do, ['GET relay/ABC.html', 'HEAD relay/ABC/index.html']);
  assert.deepEqual(r2.requests, []);
});

test('a missing page is a 404 after every source misses', async () => {
  const origins = mockOrigins();
  const r2 = mockR2();
  const env = rollbackEnv(r2, { FAILOVER_ENABLED: 'true', FAILOVER_ORIGIN_URL: FAILOVER });

  const folder = await invoke('/relay/GONE/', env);
  assert.equal(folder.status, 404);
  assert.equal(await folder.text(), 'Not Found: relay/GONE/index.html');
  assert.deepEqual(origins.do, ['GET relay/GONE/index.html']);
  assert.deepEqual(r2.requests, ['get relay/GONE/index.html']);
  assert.deepEqual(origins.failover, ['GET relay/GONE/index.html']);

  origins.do.length = 0;
  origins.failover.length = 0;
  r2.requests.length = 0;
  const page = await invoke('/misc/nope', env);
  assert.equal(page.status, 404);
  assert.deepEqual(origins.do, ['GET misc/nope.html', 'HEAD misc/nope/index.html']);
  assert.deepEqual(r2.requests, ['get misc/nope.html', 'head misc/nope/index.html']);
  assert.deepEqual(origins.failover, ['GET misc/nope.html', 'HEAD misc/nope/index.html']);
  assert.deepEqual(stored, []);
});

test('file URLs are read as-is', async () => {
  for (const [path, contentType] of [
    ['/search-index.json', 'application/json'],
    ['/static/css/allium-base.css', 'text/css'],
    ['/static/images/flags/us.png', 'image/png'],
    ['/misc/all.html', 'text/html; charset=utf-8'],
    ['/metrics', 'text/plain; version=0.0.4; charset=utf-8'],
  ]) {
    const origins = mockOrigins();
    const r2 = mockR2();
    const response = await invoke(path, rollbackEnv(r2));

    assert.equal(response.status, 200, path);
    assert.equal(response.headers.get('Content-Type'), contentType, path);
    assert.deepEqual(origins.do, [`GET ${path.slice(1)}`], path);
    assert.deepEqual(r2.requests, [], path);
  }
});

test('encoded ? and # stay in the key instead of ending the storage path', async () => {
  for (const escape of ['%3F', '%23']) {
    const origins = mockOrigins();
    const r2 = mockR2();
    const response = await invoke(`/search-index.json${escape}`, rollbackEnv(r2));
    const char = decodeURIComponent(escape);

    assert.equal(response.status, 404, escape);
    assert.equal(await response.text(), `Not Found: search-index.json${escape}.html`);
    assert.deepEqual(origins.do, [
      `GET search-index.json${char}.html`,
      `HEAD search-index.json${char}/index.html`,
    ], escape);
  }
  assert.deepEqual(stored, []);
});

test('encoded backslashes cannot step outside the failover prefix', async () => {
  const origins = mockOrigins({ spaces: {}, failover: { '/secret.html': 'outside' } });
  const env = {
    STORAGE_ORDER: 'do,failover',
    DO_SPACES_URL: SPACES,
    FAILOVER_ENABLED: 'true',
    FAILOVER_ORIGIN_URL: FAILOVER,
  };

  const response = await invoke('/..%5C..%5Csecret', env);
  assert.equal(response.status, 404);
  assert.deepEqual(origins.failover, [
    'GET ..\\..\\secret.html',
    'HEAD ..\\..\\secret/index.html',
  ]);
});

test('R2 still serves when DigitalOcean is down', async () => {
  for (const spacesDown of [503, 'network']) {
    const origins = mockOrigins({ spacesDown });
    const r2 = mockR2();

    const folder = await invoke('/relay/ABC/', rollbackEnv(r2));
    assert.equal(folder.status, 200, String(spacesDown));
    assert.equal(folder.headers.get('X-Served-From'), 'cloudflare-r2');
    assert.equal(await folder.text(), '<html>relay</html>');

    const slashless = await invoke('/relay/ABC', rollbackEnv(r2));
    assert.equal(slashless.status, 307);
    assert.equal(slashless.headers.get('Location'), '/relay/ABC/');

    // A failing backend is not probed again for the folder key.
    assert.deepEqual(origins.do, ['GET relay/ABC/index.html', 'GET relay/ABC.html']);
    assert.deepEqual(r2.requests, [
      'get relay/ABC/index.html',
      'get relay/ABC.html',
      'head relay/ABC/index.html',
    ]);
  }
});

test('the failover origin receives the resolved key', async () => {
  const origins = mockOrigins({ spaces: {}, failover: OBJECTS });
  const env = {
    STORAGE_ORDER: 'do,failover',
    DO_SPACES_URL: SPACES,
    FAILOVER_ENABLED: 'true',
    FAILOVER_ORIGIN_URL: FAILOVER,
  };

  const response = await invoke('/relay/ABC/', env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('X-Served-From'), 'failover-origin');
  assert.deepEqual(origins.do, ['GET relay/ABC/index.html']);
  assert.deepEqual(origins.failover, ['GET relay/ABC/index.html']);
});

test('a chart key falls back to its key in the other layout in the same backend', async () => {
  const objects = {
    ...OBJECTS,
    'charts/relay/ABC/bandwidth-1m.png': 'moved relay chart',
    'charts/contact/c1/bandwidth-6m.png': 'moved contact chart',
    'relay/OLD/bandwidth-1m.png': 'beside chart',
  };
  for (const [path, body, probes, servedFrom] of [
    // CHARTS_LAYOUT=charts: an old URL reads the key below charts/.
    ['/relay/ABC/bandwidth-1m.png', 'moved relay chart',
      ['GET relay/ABC/bandwidth-1m.png', 'GET charts/relay/ABC/bandwidth-1m.png'], 'digitalocean-spaces; alias'],
    ['/contact/c1/bandwidth-6m.png?v=1', 'moved contact chart',
      ['GET contact/c1/bandwidth-6m.png', 'GET charts/contact/c1/bandwidth-6m.png'], 'digitalocean-spaces; alias'],
    // Back in CHARTS_LAYOUT=beside: a /charts/ URL reads the old key.
    ['/charts/relay/OLD/bandwidth-1m.png', 'beside chart',
      ['GET charts/relay/OLD/bandwidth-1m.png', 'GET relay/OLD/bandwidth-1m.png'], 'digitalocean-spaces; alias'],
    // A key that exists is read without the alias.
    ['/relay/OLD/bandwidth-1m.png', 'beside chart', ['GET relay/OLD/bandwidth-1m.png'], 'digitalocean-spaces'],
    ['/charts/relay/ABC/bandwidth-1m.png', 'moved relay chart', ['GET charts/relay/ABC/bandwidth-1m.png'], 'digitalocean-spaces'],
  ]) {
    const origins = mockOrigins({ spaces: objects });
    const r2 = mockR2(objects);
    const response = await invoke(path, rollbackEnv(r2));

    assert.equal(response.status, 200, path);
    assert.equal(await response.text(), body, path);
    assert.equal(response.headers.get('Content-Type'), 'image/png', path);
    assert.equal(response.headers.get('X-Served-From'), servedFrom, path);
    assert.deepEqual(origins.do, probes, path);
    assert.deepEqual(r2.requests, [], path);
  }

  // R2 gets the same alias, in both directions, when DigitalOcean has neither key.
  for (const [path, probes] of [
    ['/relay/ABC/bandwidth-1m.png', ['relay/ABC/bandwidth-1m.png', 'charts/relay/ABC/bandwidth-1m.png']],
    ['/charts/relay/OLD/bandwidth-1m.png', ['charts/relay/OLD/bandwidth-1m.png', 'relay/OLD/bandwidth-1m.png']],
  ]) {
    const origins = mockOrigins({ spaces: {} });
    const r2 = mockR2(objects);
    const response = await invoke(path, rollbackEnv(r2));
    assert.equal(response.status, 200, path);
    assert.equal(response.headers.get('X-Served-From'), 'cloudflare-r2; alias', path);
    assert.deepEqual(origins.do, probes.map((key) => `GET ${key}`), path);
    assert.deepEqual(r2.requests, probes.map((key) => `get ${key}`), path);
  }
});

test("DigitalOcean's alias wins over an older direct copy in R2", async () => {
  // Right after a switch DigitalOcean holds the new layout, while R2, synced
  // daily, still holds the old one.
  for (const [path, spaces, stale, aliasKey] of [
    ['/relay/ABC/bandwidth-1m.png', { 'charts/relay/ABC/bandwidth-1m.png': 'current' },
      { 'relay/ABC/bandwidth-1m.png': 'stale' }, 'charts/relay/ABC/bandwidth-1m.png'],
    ['/charts/relay/ABC/bandwidth-1m.png', { 'relay/ABC/bandwidth-1m.png': 'current' },
      { 'charts/relay/ABC/bandwidth-1m.png': 'stale' }, 'relay/ABC/bandwidth-1m.png'],
  ]) {
    const origins = mockOrigins({ spaces });
    const r2 = mockR2(stale);
    const response = await invoke(path, rollbackEnv(r2));
    assert.equal(response.status, 200, path);
    assert.equal(await response.text(), 'current', path);
    assert.equal(response.headers.get('X-Served-From'), 'digitalocean-spaces; alias', path);
    assert.deepEqual(origins.do, [`GET ${path.slice(1)}`, `GET ${aliasKey}`], path);
    assert.deepEqual(r2.requests, [], path);
  }
});

test('an alias answer records a served-alias source event', async () => {
  const points = [];
  mockOrigins({ spaces: { 'charts/relay/ABC/bandwidth-1m.png': 'png' } });
  const response = await invoke('/relay/ABC/bandwidth-1m.png', rollbackEnv(mockR2({}), {
    SOURCE_EVENTS: { writeDataPoint(point) { points.push(point); } },
  }));
  assert.equal(response.status, 200);
  assert.deepEqual(points.map((point) => point.blobs.slice(0, 3)), [['digitalocean-spaces', 'served-alias', 'static']]);
});

test('a folder redirect from a fallback backend records a redirect-folder source event', async () => {
  const points = [];
  const events = { SOURCE_EVENTS: { writeDataPoint(point) { points.push(point); } } };
  mockOrigins({ spacesDown: 503 });
  const fallback = await invoke('/relay/ABC', rollbackEnv(mockR2(), events));
  assert.equal(fallback.status, 307);
  assert.deepEqual(points.map((point) => point.blobs.slice(0, 2)), [['cloudflare-r2', 'redirect-folder']]);

  // A redirect from the primary is routine and is not persisted.
  points.length = 0;
  mockOrigins();
  const primary = await invoke('/relay/ABC', rollbackEnv(mockR2(), events));
  assert.equal(primary.status, 307);
  assert.deepEqual(points, []);
});

test('an alias answer is not cached under the requested URL', async () => {
  stored.length = 0;
  mockOrigins({ spaces: { 'charts/relay/ABC/bandwidth-1m.png': 'png' } });
  const response = await invoke('/relay/ABC/bandwidth-1m.png', rollbackEnv(mockR2({})));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('X-Served-From'), 'digitalocean-spaces; alias');
  assert.equal(response.headers.get('X-Cache-Status'), 'BYPASS');
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal(response.headers.get('CDN-Cache-Control'), 'no-store');
  assert.deepEqual(stored, []);

  // A direct answer is still cached.
  mockOrigins({ spaces: { 'relay/ABC/bandwidth-1m.png': 'png' } });
  const direct = await invoke('/relay/ABC/bandwidth-1m.png', rollbackEnv(mockR2({})));
  assert.equal(direct.headers.get('X-Cache-Status'), 'MISS');
  assert.match(direct.headers.get('Cache-Control'), /^public, max-age=\d+$/);
  assert.equal(stored.length, 1);
});

test('only chart keys fall back to the other layout', async () => {
  for (const [path, alias] of [
    ['/relay/GONE/bandwidth-1m.png', 'charts/relay/GONE/bandwidth-1m.png'],
    ['/charts/contact/GONE/bandwidth-1m.png', 'contact/GONE/bandwidth-1m.png'],
  ]) {
    const missing = mockOrigins();
    const response = await invoke(path, rollbackEnv(mockR2()));
    assert.equal(response.status, 404, path);
    assert.deepEqual(missing.do, [`GET ${path.slice(1)}`, `GET ${alias}`], path);
  }

  for (const path of [
    '/relay/x.png',
    '/relay/ABC/sub/x.png',
    '/static/images/flags/xx.png',
    '/relay/ABC/bandwidth-1m.svg',
    '/family/ABC/bandwidth-1m.png',
    '/charts/relay/x.png',
    '/charts/relay/ABC/sub/x.png',
    '/charts/family/ABC/bandwidth-1m.png',
    '/charts/charts/relay/ABC/bandwidth-1m.png',
    '/charts/404.html',
  ]) {
    const origins = mockOrigins();
    const r2 = mockR2();
    const response = await invoke(path, rollbackEnv(r2));
    assert.equal(response.status, 404, path);
    assert.deepEqual(origins.do, [`GET ${path.slice(1)}`], path);
  }
});
