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
 */

import { getMimeType, isStaticAsset, SECURITY_HEADERS_HTML } from './_shared.js';

// === Utility Functions ===

function getCacheTTL(path, env) {
  if (isStaticAsset(path)) {
    return parseInt(env.CACHE_TTL_STATIC) || 86400;
  }
  return parseInt(env.CACHE_TTL_HTML) || 1800;
}

function normalizePath(params) {
  let path = '';
  if (Array.isArray(params.path)) {
    path = params.path.join('/');
  } else if (params.path) {
    path = String(params.path);
  }
  if (!path || path === '') return 'index.html';
  if (path.endsWith('/')) return path + 'index.html';
  return path;
}

function getCacheKey(request) {
  const url = new URL(request.url);
  return new Request(`${url.origin}${url.pathname}`, { method: 'GET' });
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

async function fetchFromR2(env, path) {
  if (!env.METRICS_CONTENT) return null;

  let object = await env.METRICS_CONTENT.get(path);
  let actualPath = path;

  // Try with /index.html for directory requests
  if (!object && !path.endsWith('.html')) {
    const pathWithIndex = `${path}/index.html`;
    object = await env.METRICS_CONTENT.get(pathWithIndex);
    if (object) actualPath = pathWithIndex;
  }

  if (!object) return null;

  return buildResponse(object.body, actualPath, 'cloudflare-r2', env);
}

async function fetchFromSpaces(env, path) {
  const baseUrl = env.DO_SPACES_URL;
  if (!baseUrl) return null;

  const url = `${baseUrl.replace(/\/$/, '')}/${path}`;
  let response = await fetch(url, {
    headers: { 'User-Agent': 'Cloudflare-Pages/1.0' },
  });

  let actualPath = path;

  // Try with /index.html for directory requests
  if (response.status === 404 && !path.endsWith('.html')) {
    const pathWithIndex = `${path}/index.html`;
    const urlWithIndex = `${baseUrl.replace(/\/$/, '')}/${pathWithIndex}`;
    response = await fetch(urlWithIndex, {
      headers: { 'User-Agent': 'Cloudflare-Pages/1.0' },
    });
    if (response.ok) actualPath = pathWithIndex;
  }

  if (!response.ok) return null;

  return buildResponse(response.body, actualPath, 'digitalocean-spaces', env);
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

// === Source Chain ===

// Storage backend definitions
const STORAGE_BACKENDS = {
  r2: { name: 'cloudflare-r2', fetch: fetchFromR2 },
  do: { name: 'digitalocean-spaces', fetch: fetchFromSpaces },
  failover: { name: 'failover-origin', fetch: fetchFromFailover },
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
  const { request, env, params } = context;
  const path = normalizePath(params);

  // Handle /_purge endpoint
  if (path === '_purge' && request.method === 'POST') {
    return handlePurge(request, env);
  }

  // Check edge cache first
  const cache = caches.default;
  const cacheKey = getCacheKey(request);
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
      const response = await source.fetch(env, path);
      if (response) {
        // Clone for cache, return original
        const responseToCache = response.clone();
        context.waitUntil(cache.put(cacheKey, responseToCache));

        response.headers.set('X-Cache-Status', 'MISS');
        return response;
      }
    } catch (err) {
      console.error(`${source.name} error for ${path}: ${err.message}`);
      lastError = err;
    }
  }

  // Nothing found
  return new Response(`Not Found: ${path}`, {
    status: 404,
    headers: {
      'Content-Type': 'text/plain',
      'X-Cache-Status': 'MISS',
      'X-Error': lastError?.message || 'not-found',
    },
  });
}
