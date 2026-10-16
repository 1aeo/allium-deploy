/**
 * Cloudflare Pages Function - Multi-Storage with Cloudflare CDN Edge Caching
 * 
 * Serves content from multiple storage backends with configurable fetch order.
 * Supports: R2 (native binding), DO Spaces (HTTP), Origin failover
 * 
 * Environment Variables:
 *   STORAGE_ORDER       - Comma-separated fetch order: "r2,do,failover" (default)
 *                         Options: r2, do, failover
 *                         Examples: "r2,do,failover", "do,r2,failover", "do,failover"
 *   DO_SPACES_URL       - Base URL for DO Spaces (required if 'do' in STORAGE_ORDER)
 *   FAILOVER_ORIGIN_URL - Failover origin URL (required if 'failover' in STORAGE_ORDER)
 *   CACHE_TTL_HTML      - Cloudflare CDN cache TTL for HTML (default: 1800 = 30 min)
 *   CACHE_TTL_STATIC    - Cloudflare CDN cache TTL for static assets (default: 86400 = 24h)
 *   PURGE_SECRET        - Secret for /_purge endpoint (Cloudflare CDN cache purge)
 * 
 * R2 Binding (required if 'r2' in STORAGE_ORDER):
 *   METRICS_CONTENT - R2 bucket binding
 *
 * Path resolution mirrors production's Workers Static Assets
 * html_handling = "auto-trailing-slash", resolved before any storage request:
 *   /, /dir/   -> index.html, dir/index.html
 *   /file.ext  -> file.ext (known extensions, plus the /metrics endpoint)
 *   /page      -> page.html; if only page/index.html exists, 307 to /page/
 *
 * With the deploy's CHARTS_LAYOUT=charts the chart PNGs live below charts/,
 * and the Workers site redirects the old chart URLs there. A chart key missing
 * in a backend is read there under its key in the other layout: an old key
 * (relay/<fingerprint>/<name>.png or contact/<hash>/<name>.png) as
 * charts/<old key>, and charts/<old key> as the old key, so that both URLs
 * work in either layout. The alias is tried in the same backend before the
 * next one, whose copy may be older. An alias answer says so in
 * X-Served-From ("<backend>; alias") and in its source event (served-alias).
 */

import { getExtension, getMimeType, isStaticAsset, MIME_TYPES, SECURITY_HEADERS_HTML } from './_shared.js';

// === Utility Functions ===

function getCacheTTL(path, env) {
  if (isStaticAsset(path)) {
    return parseInt(env.CACHE_TTL_STATIC) || 86400;
  }
  return parseInt(env.CACHE_TTL_HTML) || 1800;
}

// Pages drops the trailing empty segment from params.path for folder URLs
// (/relay/X/ arrives as ['relay', 'X']), so read the path from the URL.
// Escapes stay encoded, as they were in params: the origins decode them
// themselves, and a decoded ?, # or \ would change the storage URL's path.
function getRequestPath(url) {
  return url.pathname.replace(/^\/+/, '');
}

// Returns the storage key to read first and, for extension-less page URLs,
// the folder key whose presence answers with a redirect to the slash form.
function resolveObjectKey(path) {
  if (path === '' || path.endsWith('/')) return { key: `${path}index.html` };
  if (path === 'metrics' || path.endsWith('/metrics') ||
      Object.hasOwn(MIME_TYPES, getExtension(path))) {
    return { key: path };
  }
  return { key: `${path}.html`, folderKey: `${path}/index.html` };
}

const OLD_CHART_KEY = /^(relay|contact)\/[^/]+\/[^/]+\.png$/;
const MOVED_CHART_KEY = /^charts\/((?:relay|contact)\/[^/]+\/[^/]+\.png)$/;

// The key a chart PNG has in the other CHARTS_LAYOUT, or null for any other key.
function chartAliasKey(path) {
  if (OLD_CHART_KEY.test(path)) return `charts/${path}`;
  const moved = MOVED_CHART_KEY.exec(path);
  return moved ? moved[1] : null;
}

// DigitalOcean answers 403, not 404, for a missing key in this bucket.
function isMissingStatus(status) {
  return status === 404 || status === 403;
}

function redirectToFolder(url, source) {
  // Collapse leading slashes so //host/page cannot become an off-site
  // protocol-relative Location.
  const pathname = url.pathname.replace(/^\/+/, '/');
  return new Response(null, {
    status: 307,
    headers: {
      'Location': `${pathname}/${url.search}`,
      'X-Served-From': source,
    },
  });
}

function getCacheKey(request, env, pathSuffix = '') {
  const url = new URL(request.url);
  let cacheOrigin = url.origin;

  if (env.CACHE_KEY_ORIGIN) {
    try {
      const configured = new URL(env.CACHE_KEY_ORIGIN);
      if (configured.protocol === 'https:' && configured.username === '' &&
          configured.password === '' && configured.pathname === '/' &&
          configured.search === '' && configured.hash === '') {
        cacheOrigin = configured.origin;
      }
    } catch {
      // A malformed optional setting must not affect content availability.
      // The deploy generator validates it; fall back to the request origin.
    }
  }

  return new Request(`${cacheOrigin}${url.pathname}${pathSuffix}`, { method: 'GET' });
}

function getRouteCategory(path) {
  if (path === 'metrics' || path.endsWith('/metrics')) return 'metrics';
  const extension = path.includes('.') ? path.split('.').pop().toLowerCase() : '';
  if (extension === 'json') return 'json';
  if (extension === 'html' || path.endsWith('/index.html')) return 'html';
  if (isStaticAsset(path)) return 'static';
  return 'other';
}

function recordSourceEvent(env, request, source, status, path) {
  if (!env.SOURCE_EVENTS) return;
  // DigitalOcean is the expected primary during migration. Persist only the
  // rare evidence that X-Served-From previously exposed ephemerally: a page
  // or a folder redirect from any other backend, whose copy may be stale.
  if (source === 'digitalocean-spaces' && (status === 'served' || status === 'redirect-folder')) return;

  try {
    env.SOURCE_EVENTS.writeDataPoint({
      indexes: ['allium-source'],
      blobs: [
        source,
        status,
        getRouteCategory(path),
        request.cf?.colo || 'unknown',
      ],
      doubles: [1],
    });
  } catch {
    // Observability must never affect content delivery.
  }
}

function buildResponse(body, path, source, env) {
  const cacheTTL = getCacheTTL(path, env);
  const contentType = getMimeType(path);
  const isHtml = contentType.startsWith('text/html');
  
  const headers = {
    'Content-Type': contentType,
    'Cache-Control': `public, max-age=${cacheTTL}`,
    'CDN-Cache-Control': `public, max-age=${cacheTTL}`,
    'X-Served-From': source,
    'X-Cache-TTL': String(cacheTTL),
    // Add security headers for HTML responses
    ...(isHtml ? SECURITY_HEADERS_HTML : {}),
  };
  
  return new Response(body, { status: 200, headers });
}

// === Storage Fetchers ===

// Fetchers take a resolved storage key and return a Response, or null when
// the key is missing. A thrown error moves on to the next backend.

async function fetchFromR2(env, path) {
  if (!env.METRICS_CONTENT) return null;

  const object = await env.METRICS_CONTENT.get(path);
  if (!object) return null;

  return buildResponse(object.body, path, 'cloudflare-r2', env);
}

async function existsInR2(env, path) {
  if (!env.METRICS_CONTENT) return false;
  return Boolean(await env.METRICS_CONTENT.head(path));
}

async function requestFromSpaces(env, path, method) {
  const baseUrl = env.DO_SPACES_URL;
  if (!baseUrl) return null;

  const response = await fetch(`${baseUrl.replace(/\/$/, '')}/${path}`, {
    method,
    headers: { 'User-Agent': 'Cloudflare-Pages/1.0' },
  });
  if (isMissingStatus(response.status)) return null;
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response;
}

async function fetchFromSpaces(env, path) {
  const response = await requestFromSpaces(env, path, 'GET');
  if (!response) return null;

  return buildResponse(response.body, path, 'digitalocean-spaces', env);
}

async function existsInSpaces(env, path) {
  return Boolean(await requestFromSpaces(env, path, 'HEAD'));
}

async function fetchFromFailover(env, path) {
  if (env.FAILOVER_ENABLED !== 'true' || !env.FAILOVER_ORIGIN_URL) return null;

  const baseUrl = env.FAILOVER_ORIGIN_URL.replace(/\/$/, '');
  const url = `${baseUrl}/${path}`;

  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'Cloudflare-Pages-Failover/1.0' },
    });

    if (!response.ok) return null;

    const contentType = response.headers.get('Content-Type') || getMimeType(path);
    return new Response(response.body, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=3600',
        'X-Served-From': 'failover-origin',
      },
    });
  } catch (err) {
    console.error(`Failover error: ${err.message}`);
    return null;
  }
}

async function existsInFailover(env, path) {
  if (env.FAILOVER_ENABLED !== 'true' || !env.FAILOVER_ORIGIN_URL) return false;

  const baseUrl = env.FAILOVER_ORIGIN_URL.replace(/\/$/, '');
  try {
    const response = await fetch(`${baseUrl}/${path}`, {
      method: 'HEAD',
      headers: { 'User-Agent': 'Cloudflare-Pages-Failover/1.0' },
    });
    return response.ok;
  } catch (err) {
    console.error(`Failover error: ${err.message}`);
    return false;
  }
}

// === Source Chain ===

// Storage backend definitions
const STORAGE_BACKENDS = {
  r2: { name: 'cloudflare-r2', fetch: fetchFromR2, exists: existsInR2 },
  do: { name: 'digitalocean-spaces', fetch: fetchFromSpaces, exists: existsInSpaces },
  failover: { name: 'failover-origin', fetch: fetchFromFailover, exists: existsInFailover },
};

function getSourceChain(env) {
  // Parse STORAGE_ORDER: "r2,do,failover" -> ["r2", "do", "failover"]
  const orderStr = env.STORAGE_ORDER || 'r2,do,failover';
  const order = orderStr.split(',').map(s => s.trim().toLowerCase());
  
  const sources = [];
  
  for (const backend of order) {
    if (backend === 'r2' && env.METRICS_CONTENT) {
      sources.push(STORAGE_BACKENDS.r2);
    } else if (backend === 'do' && env.DO_SPACES_URL) {
      sources.push(STORAGE_BACKENDS.do);
    } else if (backend === 'failover' && env.FAILOVER_ORIGIN_URL) {
      sources.push(STORAGE_BACKENDS.failover);
    }
  }
  
  return sources;
}

// === Cache Purge Handler ===

async function handlePurge(request, env) {
  const secret = request.headers.get('X-Purge-Secret');
  if (!env.PURGE_SECRET) {
    return new Response('PURGE_SECRET not configured', { status: 501 });
  }
  if (secret !== env.PURGE_SECRET) {
    return new Response('Unauthorized', { status: 401 });
  }

  const cache = caches.default;
  const origin = new URL(request.url).origin;

  try {
    const body = await request.json();

    if (body.purge_all) {
      return Response.json({
        success: true,
        message: 'purge_all not supported. Provide specific URLs or wait for TTL.',
      });
    }

    let purged = 0;
    const errors = [];

    if (Array.isArray(body.urls)) {
      for (const path of body.urls) {
        try {
          const urlToPurge = path.startsWith('http') ? path : `${origin}/${path.replace(/^\//, '')}`;
          const deleted = await cache.delete(new Request(urlToPurge, { method: 'GET' }));
          if (deleted) purged++;
        } catch (e) {
          errors.push({ path, error: e.message });
        }
      }
    }

    return Response.json({
      success: true,
      purged,
      requested: body.urls?.length || 0,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 400 });
  }
}

// === Main Handler ===

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const requestPath = getRequestPath(url);

  // Handle /_purge endpoint
  if (requestPath === '_purge' && request.method === 'POST') {
    return handlePurge(request, env);
  }

  const { key: path, folderKey } = resolveObjectKey(requestPath);
  const aliasKey = chartAliasKey(path);

  // Check edge cache first. An extension-less page shares its .html URL's
  // entry, which is the key the post-upload purge already sends.
  const cache = caches.default;
  const cacheKey = getCacheKey(request, env, folderKey ? '.html' : '');
  const cached = await cache.match(cacheKey);

  if (cached) {
    const response = new Response(cached.body, cached);
    response.headers.set('X-Cache-Status', 'HIT');
    return response;
  }

  // Try each source in chain
  const sources = getSourceChain(env);
  let lastError = null;

  for (const source of sources) {
    try {
      let response = await source.fetch(env, path);
      let status = 'served';
      if (!response && aliasKey) {
        response = await source.fetch(env, aliasKey);
        if (response) {
          status = 'served-alias';
          response.headers.set('X-Served-From', `${source.name}; alias`);
          // Nor may a browser or another cache keep it under this URL.
          response.headers.set('Cache-Control', 'no-store');
          response.headers.set('CDN-Cache-Control', 'no-store');
        }
      }
      if (response) {
        // Clone for cache, return original. An alias answer is not cached: it
        // only bridges a layout switch, and a cached copy under this URL
        // would keep answering after the mirrors hold the URL's own key, for
        // example after a later switch back.
        if (status === 'served') {
          const responseToCache = response.clone();
          context.waitUntil(cache.put(cacheKey, responseToCache));
        }

        response.headers.set('X-Cache-Status', status === 'served' ? 'MISS' : 'BYPASS');
        recordSourceEvent(env, request, source.name, status, path);
        return response;
      }
      // Only page/index.html exists: redirect to /page/ like production.
      // This costs one extra request (a HEAD) on the slashless URL only.
      if (folderKey && await source.exists(env, folderKey)) {
        recordSourceEvent(env, request, source.name, 'redirect-folder', path);
        return redirectToFolder(url, source.name);
      }
    } catch (err) {
      console.error(`${source.name} error for ${path}: ${err.message}`);
      lastError = err;
    }
  }

  // Nothing found
  recordSourceEvent(env, request, 'none', 'all-sources-failed', path);
  return new Response(`Not Found: ${path}`, {
    status: 404,
    headers: {
      'Content-Type': 'text/plain',
      'X-Cache-Status': 'MISS',
      'X-Error': lastError?.message || 'not-found',
    },
  });
}
