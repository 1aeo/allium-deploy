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
 *   - Lazy case conversion (only when needed)
 *   - Combined linear scans (prefix + contains in one pass)
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
const MAX_RESULTS = 20;

// Precompiled regex patterns (ReDoS-safe, all O(n) complexity)
const RE_ALLOWED_CHARS = /^[\w\s.\-:@]+$/;
const RE_FULL_FINGERPRINT = /^[A-Fa-f0-9]{40}$/;
const RE_PARTIAL_FINGERPRINT = /^[A-Fa-f0-9]{6,39}$/;
const RE_AS_NUMBER = /^(?:AS)?(\d{1,10})$/i;
const RE_COUNTRY_CODE = /^[A-Za-z]{2}$/;
const RE_IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const RE_IPV6_CHARS = /^[A-Fa-f0-9:]+$/;
const RE_SAFE_PATH = /^[\w-]+$/;

// Precomputed Sets for O(1) membership lookups
const KNOWN_PLATFORMS = new Set(['linux', 'freebsd', 'windows', 'darwin', 'openbsd', 'netbsd', 'sunos']);
const KNOWN_FLAGS = new Set(['authority', 'badexit', 'exit', 'fast', 'guard', 'hsdir', 'named', 'running', 'stable', 'v2dir', 'valid']);

// Path prefixes for redirect validation (Array - we need startsWith, not Set membership)
const SAFE_REDIRECT_PREFIXES = Object.freeze(['/relay/', '/family/', '/contact/', '/as/', '/country/', '/platform/', '/flag/', '/first_seen/']);

// Precomputed CSP header string
const CSP_HEADER = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'";

// Precomputed frozen headers object (reused for all HTML responses)
const SECURITY_HEADERS = Object.freeze({
  'Content-Type': 'text/html; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': CSP_HEADER,
});

// Result type to URL path segment (DRY: single source of truth)
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
const HTML_HEAD_START = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>';
const HTML_HEAD_END = ' - Allium</title>\n<link rel="stylesheet" href="/static/css/bootstrap.min.css">\n<style>body{padding:40px 20px;max-width:800px;margin:0 auto}.search-box{margin-bottom:30px}.results{margin-top:20px}.result-item{padding:10px;border-bottom:1px solid #eee}.result-item:hover{background:#f8f9fa}.result-item a{text-decoration:none}.fp{font-family:monospace;font-size:.85em;color:#666}.hint{color:#666;font-style:italic;margin-bottom:15px}.back{margin-top:20px}</style>\n</head>\n<body>\n';
const HTML_FORM_START = '<div class="search-box"><form action="/search" method="get"><div class="input-group"><input type="text" name="q" class="form-control" placeholder="Search by fingerprint, nickname, AS, country, IP..." value="';
const HTML_FORM_END = `" maxlength="${MAX_QUERY_LENGTH}" autofocus><button class="btn btn-primary" type="submit">Search</button></div></form></div>\n`;
const HTML_FOOTER = '<p class="back"><a href="/">← Back to home</a></p>\n</body>\n</html>';
const HTML_ERROR_BODY = '<h2>Search Temporarily Unavailable</h2>\n<p>Please try again in a few moments.</p>\n';
const HTML_TIPS = '<h4>Search Tips</h4>\n<ul>\n<li><strong>Fingerprint:</strong> 6+ hex characters (e.g., <code>ABCD1234</code>)</li>\n<li><strong>Nickname:</strong> Relay name (e.g., <code>MyRelay</code>)</li>\n<li><strong>AS Number:</strong> With or without prefix (e.g., <code>AS24940</code> or <code>24940</code>)</li>\n<li><strong>Country:</strong> Code or name (e.g., <code>de</code> or <code>Germany</code>)</li>\n<li><strong>IP Address:</strong> IPv4 or IPv6</li>\n<li><strong>Contact:</strong> AROI domain (e.g., <code>example.org</code>)</li>\n</ul>\n';

// =============================================================================
// HTML ESCAPING (XSS Prevention)
// =============================================================================

const HTML_ESCAPE_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' };
const HTML_ESCAPE_RE = /[&<>"']/g;

function escapeHtml(s) {
  return s ? String(s).replace(HTML_ESCAPE_RE, c => HTML_ESCAPE_MAP[c]) : '';
}

// =============================================================================
// INDEX CACHE WITH PRECOMPUTED LOOKUP MAPS
// =============================================================================

let cachedIndex = null;
let cacheExpiry = 0;

/**
 * Build optimized lookup structures from raw index.
 * Single pass over each array for efficiency.
 */
function buildLookupMaps(raw) {
  const relays = raw.relays || [];
  
  // O(1) lookup maps
  const fpMap = new Map();
  const nickMap = new Map();  // lowercase nickname -> relay
  const ipMap = new Map();
  const asSet = new Set();
  const ccSet = new Set();
  const ccNameMap = new Map();
  const contactDomainMap = new Map();
  const contactHashMap = new Map();
  const familyIdMap = new Map();
  const familyPrefixMap = new Map();

  // Single pass over relays
  for (let i = 0; i < relays.length; i++) {
    const r = relays[i];
    if (r.f) fpMap.set(r.f, r);
    if (r.n && !nickMap.has(r.n.toLowerCase())) nickMap.set(r.n.toLowerCase(), r);
    if (r.as) asSet.add(r.as.toUpperCase());
    if (r.cc) ccSet.add(r.cc.toLowerCase());
    if (r.ip) {
      const ips = Array.isArray(r.ip) ? r.ip : [r.ip];
      for (let j = 0; j < ips.length; j++) ipMap.set(ips[j], r);
    }
  }

  // AS entries
  const asList = raw.autonomous_systems || [];
  for (let i = 0; i < asList.length; i++) {
    const a = asList[i];
    if (a.num) asSet.add(a.num.toUpperCase());
  }

  // Countries
  const countries = raw.countries || [];
  for (let i = 0; i < countries.length; i++) {
    const c = countries[i];
    if (c.code) ccSet.add(c.code.toLowerCase());
    if (c.name && c.code) ccNameMap.set(c.name.toLowerCase(), c.code.toLowerCase());
  }

  // Contacts
  const contacts = raw.contacts || [];
  for (let i = 0; i < contacts.length; i++) {
    const c = contacts[i];
    if (c.domain) contactDomainMap.set(c.domain.toLowerCase(), c);
    if (c.hash) contactHashMap.set(c.hash.toLowerCase(), c);
  }

  // Families
  const families = raw.families || [];
  for (let i = 0; i < families.length; i++) {
    const f = families[i];
    if (f.id) familyIdMap.set(f.id, f);
    if (f.prefix) familyPrefixMap.set(f.prefix.toLowerCase(), f);
  }

  return Object.freeze({
    relays,
    fpMap,
    nickMap,
    ipMap,
    asSet,
    ccSet,
    ccNameMap,
    contactDomainMap,
    contactHashMap,
    familyIdMap,
    familyPrefixMap,
  });
}

async function loadIndex(origin) {
  const now = Date.now();
  if (cachedIndex && now < cacheExpiry) return cachedIndex;
  
  const res = await fetch(`${origin}/search-index.json`, {
    cf: { cacheTtl: 300, cacheEverything: true },
  });
  if (!res.ok) throw new Error(`Index load failed: ${res.status}`);
  
  cachedIndex = buildLookupMaps(await res.json());
  cacheExpiry = now + INDEX_CACHE_TTL_MS;
  return cachedIndex;
}

// =============================================================================
// INPUT VALIDATION
// =============================================================================

function validateQuery(raw) {
  if (!raw || typeof raw !== 'string') return { ok: false, q: '', err: 'empty' };
  const q = raw.trim();
  if (!q) return { ok: false, q: '', err: 'empty' };
  if (q.length > MAX_QUERY_LENGTH) return { ok: false, q: '', err: `Query too long (max ${MAX_QUERY_LENGTH} chars)` };
  if (!RE_ALLOWED_CHARS.test(q)) return { ok: false, q: '', err: 'Query contains invalid characters' };
  return { ok: true, q, err: '' };
}

function isSafePath(s) {
  return s && s.length <= 100 && RE_SAFE_PATH.test(s);
}

// =============================================================================
// RESPONSE HELPERS
// =============================================================================

function htmlResponse(body, status) {
  return new Response(body, { status, headers: SECURITY_HEADERS });
}

function safeRedirect(origin, path) {
  // Validate against prefix allowlist
  let ok = false;
  for (let i = 0; i < SAFE_REDIRECT_PREFIXES.length; i++) {
    if (path.startsWith(SAFE_REDIRECT_PREFIXES[i])) { ok = true; break; }
  }
  if (!ok || path.includes('://') || path.startsWith('//')) {
    console.error('Blocked redirect:', path);
    return new Response('Invalid redirect', { status: 400 });
  }
  return Response.redirect(new URL(path, origin).href, 302);
}

function handleError(err, q) {
  console.error('Search error:', { msg: err.message, q: q?.slice(0, 50) });
  return htmlResponse(HTML_HEAD_START + 'Error' + HTML_HEAD_END + HTML_ERROR_BODY + HTML_FOOTER, 503);
}

// =============================================================================
// SEARCH LOGIC
// =============================================================================

/**
 * Map relay to result format for disambiguation.
 */
function relayResult(r) {
  return { t: 'relay', f: r.f, n: r.n, cc: r.cc };
}

/**
 * Search index with optimized lookups.
 * Fast O(1) checks first, linear scans only as fallback.
 */
function search(q, idx) {
  // 1. Full fingerprint - O(1) Map lookup
  if (RE_FULL_FINGERPRINT.test(q)) {
    const qUp = q.toUpperCase();
    const relay = idx.fpMap.get(qUp);
    if (relay) return { type: 'relay', id: relay.f };
    const family = idx.familyIdMap.get(qUp);
    if (family) return { type: 'family', id: family.id };
    return { type: 'not_found' };
  }

  // 2. Partial fingerprint - scan Map keys
  if (RE_PARTIAL_FINGERPRINT.test(q)) {
    const qUp = q.toUpperCase();
    const matches = [];
    for (const [fp, r] of idx.fpMap) {
      if (fp.startsWith(qUp)) {
        matches.push(r);
        if (matches.length > MAX_RESULTS) break;
      }
    }
    if (matches.length === 1) return { type: 'relay', id: matches[0].f };
    if (matches.length > 1) {
      return { type: 'multiple', matches: matches.slice(0, MAX_RESULTS).map(relayResult), hint: 'Multiple relays match this fingerprint prefix' };
    }
  }

  const qLow = q.toLowerCase();

  // 3. AS number - O(1) Set lookup
  const asMatch = q.match(RE_AS_NUMBER);
  if (asMatch) {
    const asNum = 'AS' + asMatch[1];
    if (idx.asSet.has(asNum)) return { type: 'as', id: asNum };
  }

  // 4. Country code - O(1) Set lookup
  if (RE_COUNTRY_CODE.test(q) && idx.ccSet.has(qLow)) {
    return { type: 'country', id: qLow };
  }

  // 5. Country name - O(1) Map lookup
  const ccByName = idx.ccNameMap.get(qLow);
  if (ccByName) return { type: 'country', id: ccByName };

  // 6. Platform - O(1) Set lookup
  if (KNOWN_PLATFORMS.has(qLow)) return { type: 'platform', id: qLow };

  // 7. Flag - O(1) Set lookup
  if (KNOWN_FLAGS.has(qLow)) return { type: 'flag', id: qLow };

  // 8. Contact domain/hash - O(1) Map lookups
  const cDomain = idx.contactDomainMap.get(qLow);
  if (cDomain) return { type: 'contact', id: cDomain.hash };
  const cHash = idx.contactHashMap.get(qLow);
  if (cHash) return { type: 'contact', id: cHash.hash };

  // 9. IP address - O(1) Map lookup
  if (RE_IPV4.test(q) || (q.includes(':') && RE_IPV6_CHARS.test(q))) {
    const relay = idx.ipMap.get(q);
    if (relay) return { type: 'relay', id: relay.f };
  }

  // 10. Exact nickname - O(1) Map lookup
  const exactNick = idx.nickMap.get(qLow);
  if (exactNick) return { type: 'relay', id: exactNick.f };

  // 11. Family prefix - O(1) Map lookup
  const famByPrefix = idx.familyPrefixMap.get(qLow);
  if (famByPrefix) return { type: 'family', id: famByPrefix.id };

  // 12. Nickname prefix/contains - Combined single pass (DRY + efficient)
  const prefixMatches = [];
  const containsMatches = [];
  const relays = idx.relays;
  
  for (let i = 0; i < relays.length; i++) {
    const r = relays[i];
    if (!r.n) continue;
    const nLow = r.n.toLowerCase();
    
    if (nLow.startsWith(qLow)) {
      prefixMatches.push(r);
      if (prefixMatches.length > MAX_RESULTS) break;
    } else if (containsMatches.length <= MAX_RESULTS * 2 && nLow.includes(qLow)) {
      containsMatches.push(r);
    }
  }

  // Prefer prefix matches over contains
  if (prefixMatches.length === 1) return { type: 'relay', id: prefixMatches[0].f };
  if (prefixMatches.length > 1) {
    // Check if all share same family
    let famId = null, sameFam = true;
    for (let i = 0; i < prefixMatches.length && sameFam; i++) {
      const f = prefixMatches[i].fam;
      if (!f) { sameFam = false; }
      else if (!famId) { famId = f; }
      else if (famId !== f) { sameFam = false; }
    }
    if (sameFam && famId) return { type: 'family', id: famId };
    return { type: 'multiple', matches: prefixMatches.slice(0, MAX_RESULTS).map(relayResult), hint: `Multiple relays match "${q}"` };
  }

  // Fall back to contains matches
  if (containsMatches.length === 1) return { type: 'relay', id: containsMatches[0].f };
  if (containsMatches.length > 1 && containsMatches.length <= MAX_RESULTS * 2) {
    return { type: 'multiple', matches: containsMatches.slice(0, MAX_RESULTS).map(relayResult), hint: `Found ${containsMatches.length} relays containing "${q}"` };
  }

  return { type: 'not_found' };
}

// =============================================================================
// PAGE RENDERING
// =============================================================================

function renderPage(title, content, query) {
  return HTML_HEAD_START + escapeHtml(title) + HTML_HEAD_END +
    `<h2>${escapeHtml(title)}</h2>\n` +
    HTML_FORM_START + escapeHtml(query || '') + HTML_FORM_END +
    '<div class="results">\n' + content + '</div>\n' + HTML_FOOTER;
}

function renderDisambiguation(matches, query, hint) {
  let content = hint ? `<p class="hint">${escapeHtml(hint)}</p>\n` : '';
  
  for (let i = 0; i < matches.length; i++) {
    const m = matches[i];
    if (m.t === 'relay') {
      const name = escapeHtml(m.n || 'Unnamed');
      const fp = escapeHtml(m.f);
      const cc = m.cc ? escapeHtml(m.cc.toUpperCase()) + ' ' : '';
      content += `<div class="result-item"><a href="/relay/${fp}/"><strong>${name}</strong><br><span class="fp">${cc}${fp}</span></a></div>\n`;
    }
  }
  
  return htmlResponse(renderPage('Search Results', content, query), 200);
}

function renderNotFound(query) {
  const content = `<p>No relays, families, or operators found matching "<strong>${escapeHtml(query)}</strong>".</p>\n` + HTML_TIPS;
  return htmlResponse(renderPage('No Results Found', content, query), 404);
}

function renderInvalid(error) {
  const content = `<p class="text-danger">${escapeHtml(error)}</p>\n`;
  return htmlResponse(renderPage('Invalid Search Query', content, ''), 400);
}

// =============================================================================
// REQUEST HANDLER
// =============================================================================

export async function onRequestGet(ctx) {
  const url = new URL(ctx.request.url);
  const { ok, q, err } = validateQuery(url.searchParams.get('q'));
  
  if (!ok) {
    return err === 'empty' ? Response.redirect(url.origin + '/', 302) : renderInvalid(err);
  }
  
  try {
    const idx = await loadIndex(url.origin);
    const result = search(q, idx);
    
    // Direct redirect for single-match types
    const pathType = RESULT_TYPE_PATHS[result.type];
    if (pathType && result.id) {
      if (!isSafePath(result.id)) return handleError(new Error('Invalid ID'), q);
      return safeRedirect(url.origin, `/${pathType}/${result.id}/`);
    }
    
    // Multiple matches
    if (result.type === 'multiple') {
      return renderDisambiguation(result.matches, q, result.hint);
    }
    
    return renderNotFound(q);
  } catch (e) {
    return handleError(e, q);
  }
}
