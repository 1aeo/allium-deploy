/**
 * Workers Static Assets entry point.
 *
 * Matching static assets are served before this module is invoked. The only
 * intentional dynamic route is /search. Other invocations (for example, a
 * non-navigation request for a missing path) are delegated to the assets
 * binding so Cloudflare's configured 404-page behavior remains authoritative.
 */

import { onRequest as handleSearch } from '../functions/search.js';

function isSearchPath(pathname) {
  return pathname === '/search' || pathname.startsWith('/search/');
}

export default {
  async fetch(request, env, executionCtx) {
    const url = new URL(request.url);

    if (!isSearchPath(url.pathname)) {
      return env.ALLIUM_ASSETS.fetch(request);
    }

    return handleSearch({
      request,
      env,
      waitUntil: executionCtx.waitUntil.bind(executionCtx),
      passThroughOnException: executionCtx.passThroughOnException?.bind(executionCtx),
    });
  },
};
