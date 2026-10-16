/**
 * Workers Static Assets entry point.
 *
 * Matching static assets are served before this module is invoked. The only
 * intentional dynamic route is /search. Other invocations (for example, a
 * non-navigation request for a missing path) are delegated to the assets
 * binding so Cloudflare's configured 404-page behavior remains authoritative.
 */

import { onRequest as handleSearch } from '../functions/search.js';

const REHEARSAL_HOSTNAME = 'metrics-next.1aeo.com';

function isSearchPath(pathname) {
  return pathname === '/search' || pathname.startsWith('/search/');
}

function isNonProductionHostname(hostname) {
  return hostname === REHEARSAL_HOSTNAME || hostname.endsWith('.workers.dev');
}

function withNonProductionRobotsHeader(response) {
  const headers = new Headers(response.headers);
  headers.set('X-Robots-Tag', 'noindex, nofollow');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env, executionCtx) {
    const url = new URL(request.url);

    if (!isSearchPath(url.pathname)) {
      return env.ALLIUM_ASSETS.fetch(request);
    }

    const response = await handleSearch({
      request,
      env,
      waitUntil: executionCtx.waitUntil.bind(executionCtx),
      passThroughOnException: executionCtx.passThroughOnException?.bind(executionCtx),
    });

    return isNonProductionHostname(url.hostname)
      ? withNonProductionRobotsHeader(response)
      : response;
  },
};
