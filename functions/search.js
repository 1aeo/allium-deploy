/**
 * Cloudflare Pages Function - Search Handler
 * 
 * Handles /search?q=... requests, searches the static search-index.json,
 * and returns redirects or disambiguation/not-found pages.
 * 
 * Performance Optimizations:
 *   - Lookup maps built once per index load (O(1) lookups vs O(n) scans)
 *   - Static values precomputed at module load time
 *   - Sets for O(1) membership tests
 *   - Single-pass index processing
 * 
 * Security Features:
 *   - Input validation (length limit, character allowlist)
 *   - XSS prevention (HTML escaping)
 *   - Open redirect prevention (path allowlist)
 *   - Security headers (CSP, X-Frame-Options, etc.)
 *   - ReDoS-safe regex patterns (all O(n) complexity)
 *   - Generic error messages (no internal details exposed)
 */

// =============================================================================
// PRECOMPUTED CONSTANTS (computed once at module load)
// =============================================================================

const MAX_QUERY_LENGTH = 100;
const INDEX_CACHE_TTL_MS = 300000; // 5 minutes in ms

// Precompiled regex patterns (ReDoS-safe, all O(n) complexity)
const RE_ALLOWED_CHARS = /^[\w\s.\-:@]+$/;
const RE_FULL_FINGERPRINT = /^[A-Fa-f0-9]{40}$/;
const RE_PARTIAL_FINGERPRINT = /^[A-Fa-f0-9]{6,39}$/;
const RE_AS_NUMBER = /^(?:AS)?(\d{1,10})$/i;
const RE_COUNTRY_CODE = /^[A-Za-z]{2}$/;
const RE_IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const RE_IPV6_CHARS = /^[A-Fa-f0-9:]+$/;
const RE_SAFE_PATH = /^[\w-]+$/;

// Precomputed Sets for O(1) lookups
const KNOWN_PLATFORMS = new Set(['linux', 'freebsd', 'windows', 'darwin', 'openbsd', 'netbsd', 'sunos']);
const KNOWN_FLAGS = new Set(['authority', 'badexit', 'exit', 'fast', 'guard', 'hsdir', 'named', 'running', 'stable', 'v2dir', 'valid']);

// Precomputed path prefix set for O(1) redirect validation
const SAFE_REDIRECT_PREFIXES = new Set(['/relay/', '/family/', '/contact/', '/as/', '/country/', '/platform/', '/flag/', '/first_seen/']);

// Precomputed CSP header (joined once at load time)
const CSP_HEADER = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'";

// Precomputed security headers object (reused for all responses)
const SECURITY_HEADERS = Object.freeze({
  'Content-Type': 'text/html; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': CSP_HEADER,
});

// Result type to URL path mapping (DRY: single source of truth)
const RESULT_TYPE_PATHS = Object.freeze({
  relay: 'relay',
  family: 'family',
  contact: 'contact',
  as: 'as',
  country: 'country',
  platform: 'platform',
  flag: 'flag',
});

// Precomputed static HTML fragments
const HTML_DOCTYPE = '<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>';
const HTML_TITLE_CLOSE = ' - Allium</title>\n  <link rel="stylesheet" href="/static/css/bootstrap.min.css">\n  <style>body{padding:40px 20px;max-width:800px;margin:0 auto}.search-box{margin-bottom:30px}.results{margin-top:20px}.result-item{padding:10px;border-bottom:1px solid #eee}.result-item:hover{background:#f8f9fa}.result-item a{text-decoration:none}.fingerprint{font-family:monospace;font-size:.85em;color:#666}.hint{color:#666;font-style:italic;margin-bottom:15px}.back-link{margin-top:20px}</style>\n</head>\n<body>\n';
const HTML_SEARCH_FORM_START = '  <div class="search-box">\n    <form action="/search" method="get">\n      <div class="input-group">\n        <input type="text" name="q" class="form-control" placeholder="Search by fingerprint, nickname, AS, country, IP..." value="';
const HTML_SEARCH_FORM_END = `" maxlength="${MAX_QUERY_LENGTH}" autofocus>\n        <button class="btn btn-primary" type="submit">Search</button>\n      </div>\n    </form>\n  </div>\n`;
const HTML_BACK_LINK = '  <p class="back-link"><a href="/">← Back to home</a></p>\n</body>\n</html>';
const HTML_ERROR_BODY = '  <h2>Search Temporarily Unavailable</h2>\n  <p>Please try again in a few moments.</p>\n';
const HTML_NOTFOUND_TIPS = `
    <h4>Search Tips</h4>
    <ul>
      <li><strong>Fingerprint:</strong> Enter 6+ hex characters (e.g., <code>ABCD1234</code>)</li>
      <li><strong>Nickname:</strong> Enter the relay name (e.g., <code>MyRelay</code>)</li>
      <li><strong>AS Number:</strong> Enter with or without prefix (e.g., <code>AS24940</code> or <code>24940</code>)</li>
      <li><strong>Country:</strong> Enter code or name (e.g., <code>de</code> or <code>Germany</code>)</li>
      <li><strong>IP Address:</strong> Enter IPv4 or IPv6 address</li>
      <li><strong>Contact:</strong> Enter AROI domain (e.g., <code>example.org</code>)</li>
    </ul>
`;

// =============================================================================
// INDEX CACHE WITH PRECOMPUTED LOOKUP MAPS
// =============================================================================

let cachedIndex = null;
let cacheExpiry = 0;

/**
 * Optimized index structure with O(1) lookup maps.
 * Built once when index is loaded, reused for all queries until cache expires.
 */
function buildLookupMaps(rawIndex) {
  const relays = rawIndex.relays || [];
  const contacts = rawIndex.contacts || [];
  const countries = rawIndex.countries || [];
  const autonomousSystems = rawIndex.autonomous_systems || [];
  const families = rawIndex.families || [];

  // O(1) lookup maps
  const fpMap = new Map();           // fingerprint -> relay
  const nickLowerMap = new Map();    // nickname.toLowerCase() -> relay (first match)
  const nickLowerList = new Map();   // nickname.toLowerCase() -> [relays] (all matches)
  const ipMap = new Map();           // ip -> relay
  const asSet = new Set();           // all known AS numbers (normalized)
  const ccSet = new Set();           // all known country codes (lowercase)
  const ccNameMap = new Map();       // country name lowercase -> country code
  const contactDomainMap = new Map(); // domain lowercase -> contact
  const contactHashMap = new Map();   // hash lowercase -> contact
  const familyIdMap = new Map();     // family id -> family
  const familyPrefixMap = new Map(); // prefix lowercase -> family

  // Build relay maps (single pass)
  for (const r of relays) {
    if (r.f) fpMap.set(r.f, r);
    
    if (r.n) {
      const nLower = r.n.toLowerCase();
      if (!nickLowerMap.has(nLower)) {
        nickLowerMap.set(nLower, r);
      }
      const list = nickLowerList.get(nLower) || [];
      list.push(r);
      nickLowerList.set(nLower, list);
    }
    
    if (r.ip) {
      // Handle array or string
      const ips = Array.isArray(r.ip) ? r.ip : [r.ip];
      for (const ip of ips) {
        ipMap.set(ip, r);
      }
    }
    
    if (r.as) asSet.add(r.as.toUpperCase());
    if (r.cc) ccSet.add(r.cc.toLowerCase());
  }

  // Build AS map
  for (const a of autonomousSystems) {
    if (a.num) asSet.add(a.num.toUpperCase().replace(/^AS/i, 'AS'));
  }

  // Build country maps
  for (const c of countries) {
    if (c.code) ccSet.add(c.code.toLowerCase());
    if (c.name && c.code) ccNameMap.set(c.name.toLowerCase(), c.code.toLowerCase());
  }

  // Build contact maps
  for (const c of contacts) {
    if (c.domain) contactDomainMap.set(c.domain.toLowerCase(), c);
    if (c.hash) contactHashMap.set(c.hash.toLowerCase(), c);
  }

  // Build family maps
  for (const f of families) {
    if (f.id) familyIdMap.set(f.id, f);
    if (f.prefix) familyPrefixMap.set(f.prefix.toLowerCase(), f);
  }

  return Object.freeze({
    relays,
    fpMap,
    nickLowerMap,
    nickLowerList,
    ipMap,
    asSet,
    ccSet,
    ccNameMap,
    contactDomainMap,
    contactHashMap,
    familyIdMap,
    familyPrefixMap,
    families,
  });
}

/**
 * Load and cache the search index with precomputed lookup maps.
 * 
 * @param {string} origin - The request origin URL
 * @returns {Promise<Object>} The optimized search index
 */
async function loadIndex(origin) {
  const now = Date.now();
  
  if (cachedIndex && now < cacheExpiry) {
    return cachedIndex;
  }
  
  const response = await fetch(`${origin}/search-index.json`, {
    cf: { cacheTtl: 300, cacheEverything: true },
  });
  
  if (!response.ok) {
    throw new Error(`Index load failed: ${response.status}`);
  }
  
  const rawIndex = await response.json();
  cachedIndex = buildLookupMaps(rawIndex);
  cacheExpiry = now + INDEX_CACHE_TTL_MS;
  
  return cachedIndex;
}

// =============================================================================
// INPUT VALIDATION
// =============================================================================

/**
 * Validate and sanitize user input.
 * @returns {{ valid: boolean, query: string, error: string }}
 */
function validateQuery(raw) {
  if (!raw || typeof raw !== 'string') {
    return { valid: false, query: '', error: 'empty' };
  }
  
  const q = raw.trim();
  if (!q) {
    return { valid: false, query: '', error: 'empty' };
  }
  
  if (q.length > MAX_QUERY_LENGTH) {
    return { valid: false, query: '', error: `Query too long (max ${MAX_QUERY_LENGTH} characters)` };
  }
  
  if (!RE_ALLOWED_CHARS.test(q)) {
    return { valid: false, query: '', error: 'Query contains invalid characters' };
  }
  
  return { valid: true, query: q, error: '' };
}

/**
 * Check if string is safe for URL path segment.
 */
function isSafePath(s) {
  return s && typeof s === 'string' && s.length <= 100 && RE_SAFE_PATH.test(s);
}

// =============================================================================
// HTML ESCAPING (XSS Prevention)
// =============================================================================

// Precomputed escape map for O(1) lookup per character
const HTML_ESCAPE_MAP = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
});
const HTML_ESCAPE_RE = /[&<>"']/g;

/**
 * Escape HTML special characters. Uses precompiled regex and lookup map.
 */
function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(HTML_ESCAPE_RE, c => HTML_ESCAPE_MAP[c]);
}

// =============================================================================
// RESPONSE HELPERS
// =============================================================================

/**
 * Create secure HTML response with precomputed headers.
 */
function htmlResponse(body, status = 200) {
  return new Response(body, { status, headers: SECURITY_HEADERS });
}

/**
 * Create safe redirect. Validates path prefix against allowlist.
 */
function safeRedirect(origin, path) {
  // Check prefix against Set (O(1) per prefix check, early exit)
  let allowed = false;
  for (const prefix of SAFE_REDIRECT_PREFIXES) {
    if (path.startsWith(prefix)) {
      allowed = true;
      break;
    }
  }
  
  if (!allowed || path.includes('://') || path.startsWith('//')) {
    console.error('Blocked redirect:', path);
    return new Response('Invalid redirect', { status: 400 });
  }
  
  return Response.redirect(new URL(path, origin).href, 302);
}

/**
 * Handle errors without exposing internals.
 */
function handleError(err, query) {
  console.error('Search error:', { msg: err.message, q: query?.slice(0, 50) });
  return htmlResponse(
    HTML_DOCTYPE + 'Error' + HTML_TITLE_CLOSE + HTML_ERROR_BODY + HTML_BACK_LINK,
    503
  );
}

// =============================================================================
// SEARCH LOGIC (Optimized with O(1) lookups)
// =============================================================================

/**
 * Search the index using precomputed lookup maps.
 * Priority order ensures most specific matches first.
 */
function search(query, index) {
  const q = query;
  const qLower = q.toLowerCase();
  const qUpper = q.toUpperCase();

  // 1. Full fingerprint (exact O(1) lookup)
  if (RE_FULL_FINGERPRINT.test(q)) {
    const relay = index.fpMap.get(qUpper);
    if (relay) return { type: 'relay', id: relay.f };
    
    const family = index.familyIdMap.get(qUpper);
    if (family) return { type: 'family', id: family.id };
    
    return { type: 'not_found' };
  }

  // 2. Partial fingerprint prefix
  if (RE_PARTIAL_FINGERPRINT.test(q)) {
    const matches = [];
    for (const [fp, relay] of index.fpMap) {
      if (fp.startsWith(qUpper)) {
        matches.push(relay);
        if (matches.length > 20) break; // Limit scan
      }
    }
    
    if (matches.length === 1) {
      return { type: 'relay', id: matches[0].f };
    }
    if (matches.length > 1) {
      return {
        type: 'multiple',
        matches: matches.slice(0, 20).map(r => ({ type: 'relay', f: r.f, n: r.n })),
        hint: 'Multiple relays match this fingerprint prefix',
      };
    }
    // Fall through to other checks
  }

  // 3. AS number (O(1) Set lookup)
  const asMatch = q.match(RE_AS_NUMBER);
  if (asMatch) {
    const asNum = 'AS' + asMatch[1];
    if (index.asSet.has(asNum)) {
      return { type: 'as', id: asNum };
    }
  }

  // 4. Country code (O(1) Set lookup)
  if (RE_COUNTRY_CODE.test(q) && index.ccSet.has(qLower)) {
    return { type: 'country', id: qLower };
  }

  // 5. Country name (O(1) Map lookup)
  const ccByName = index.ccNameMap.get(qLower);
  if (ccByName) {
    return { type: 'country', id: ccByName };
  }

  // 6. Platform (O(1) Set lookup)
  if (KNOWN_PLATFORMS.has(qLower)) {
    return { type: 'platform', id: qLower };
  }

  // 7. Flag (O(1) Set lookup)
  if (KNOWN_FLAGS.has(qLower)) {
    return { type: 'flag', id: qLower };
  }

  // 8. Contact by domain or hash (O(1) Map lookups)
  const contactByDomain = index.contactDomainMap.get(qLower);
  if (contactByDomain) {
    return { type: 'contact', id: contactByDomain.hash };
  }
  const contactByHash = index.contactHashMap.get(qLower);
  if (contactByHash) {
    return { type: 'contact', id: contactByHash.hash };
  }

  // 9. IP address (O(1) Map lookup)
  if (RE_IPV4.test(q) || (q.includes(':') && RE_IPV6_CHARS.test(q))) {
    const relay = index.ipMap.get(q);
    if (relay) {
      return { type: 'relay', id: relay.f };
    }
  }

  // 10. Exact nickname (O(1) Map lookup)
  const exactNick = index.nickLowerMap.get(qLower);
  if (exactNick) {
    return { type: 'relay', id: exactNick.f };
  }

  // 11. Family prefix (O(1) Map lookup)
  const familyByPrefix = index.familyPrefixMap.get(qLower);
  if (familyByPrefix) {
    return { type: 'family', id: familyByPrefix.id };
  }

  // 12. Nickname prefix search (linear scan, but rare path)
  const prefixMatches = [];
  for (const relay of index.relays) {
    if (relay.n && relay.n.toLowerCase().startsWith(qLower)) {
      prefixMatches.push(relay);
      if (prefixMatches.length > 20) break;
    }
  }
  
  if (prefixMatches.length === 1) {
    return { type: 'relay', id: prefixMatches[0].f };
  }
  if (prefixMatches.length > 1) {
    // Check if all share same family
    const famIds = new Set(prefixMatches.map(r => r.fam).filter(Boolean));
    if (famIds.size === 1) {
      return { type: 'family', id: famIds.values().next().value };
    }
    return {
      type: 'multiple',
      matches: prefixMatches.slice(0, 20).map(r => ({ type: 'relay', f: r.f, n: r.n, cc: r.cc })),
      hint: `Multiple relays match "${q}"`,
    };
  }

  // 13. Nickname contains (last resort, linear scan)
  const containsMatches = [];
  for (const relay of index.relays) {
    if (relay.n && relay.n.toLowerCase().includes(qLower)) {
      containsMatches.push(relay);
      if (containsMatches.length > 50) break;
    }
  }
  
  if (containsMatches.length === 1) {
    return { type: 'relay', id: containsMatches[0].f };
  }
  if (containsMatches.length > 1 && containsMatches.length <= 50) {
    return {
      type: 'multiple',
      matches: containsMatches.slice(0, 20).map(r => ({ type: 'relay', f: r.f, n: r.n, cc: r.cc })),
      hint: `Found ${containsMatches.length} relays containing "${q}"`,
    };
  }

  return { type: 'not_found' };
}

// =============================================================================
// PAGE RENDERING
// =============================================================================

function renderHead(title) {
  return HTML_DOCTYPE + escapeHtml(title) + HTML_TITLE_CLOSE;
}

function renderSearchForm(query) {
  return HTML_SEARCH_FORM_START + escapeHtml(query) + HTML_SEARCH_FORM_END;
}

function renderDisambiguationPage(matches, query, hint) {
  let html = renderHead('Search Results');
  html += '  <h2>Search Results</h2>\n';
  html += renderSearchForm(query);
  html += '  <div class="results">\n';
  
  if (hint) {
    html += `    <p class="hint">${escapeHtml(hint)}</p>\n`;
  }
  
  for (const m of matches) {
    if (m.type === 'relay') {
      const name = escapeHtml(m.n || 'Unnamed');
      const fp = escapeHtml(m.f);
      const cc = m.cc ? `<span style="margin-right:5px">${escapeHtml(m.cc.toUpperCase())}</span>` : '';
      html += `    <div class="result-item"><a href="/relay/${fp}/"><strong>${name}</strong><br>${cc}<span class="fingerprint">${fp}</span></a></div>\n`;
    } else if (m.type === 'family') {
      const id = escapeHtml(m.id || m.familyId);
      html += `    <div class="result-item"><a href="/family/${id}/"><strong>Family: ${id.slice(0, 8)}...</strong></a></div>\n`;
    }
  }
  
  html += '  </div>\n';
  html += HTML_BACK_LINK;
  return htmlResponse(html, 200);
}

function renderNotFoundPage(query) {
  let html = renderHead('Not Found');
  html += '  <h2>No Results Found</h2>\n';
  html += renderSearchForm(query);
  html += '  <div class="results">\n';
  html += `    <p>No relays, families, or operators found matching "<strong>${escapeHtml(query)}</strong>".</p>\n`;
  html += HTML_NOTFOUND_TIPS;
  html += '  </div>\n';
  html += HTML_BACK_LINK;
  return htmlResponse(html, 404);
}

function renderInvalidPage(error) {
  let html = renderHead('Invalid Search');
  html += '  <h2>Invalid Search Query</h2>\n';
  html += renderSearchForm('');
  html += `  <div class="results"><p class="text-danger">${escapeHtml(error)}</p></div>\n`;
  html += HTML_BACK_LINK;
  return htmlResponse(html, 400);
}

// =============================================================================
// REQUEST HANDLER
// =============================================================================

export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const raw = url.searchParams.get('q');
  
  // Validate input
  const { valid, query, error } = validateQuery(raw);
  
  if (!valid) {
    if (error === 'empty') {
      return Response.redirect(url.origin + '/', 302);
    }
    return renderInvalidPage(error);
  }
  
  try {
    const index = await loadIndex(url.origin);
    const result = search(query, index);
    
    // Handle redirect types (DRY: unified path construction)
    const pathType = RESULT_TYPE_PATHS[result.type];
    if (pathType && result.id) {
      if (!isSafePath(result.id)) {
        return handleError(new Error(`Invalid ${result.type} ID`), query);
      }
      return safeRedirect(url.origin, `/${pathType}/${result.id}/`);
    }
    
    // Handle non-redirect types
    if (result.type === 'multiple') {
      return renderDisambiguationPage(result.matches, query, result.hint);
    }
    
    return renderNotFoundPage(query);
    
  } catch (err) {
    return handleError(err, query);
  }
}
