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
 *   - Precomputed lowercase nicknames (avoids repeated toLowerCase in scans)
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

import { CONTENT_TYPE_HTML, SECURITY_HEADERS_HTML, escapeHtml } from './_shared.js';

// =============================================================================
// PRECOMPUTED CONSTANTS (computed once at module load)
// =============================================================================

const MAX_QUERY_LENGTH = 100;
const INDEX_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_RESULTS = 20;

// Precompiled regex patterns (ReDoS-safe, all O(n) complexity)
const RE_ALLOWED_CHARS = /^[\w\s.\-:@]+$/;
const RE_FULL_FINGERPRINT = /^[A-Fa-f0-9]{40}$/;
const RE_PARTIAL_FINGERPRINT = /^[A-Fa-f0-9]{6,39}$/;
const RE_AS_NUMBER = /^(?:AS)?(\d{1,10})$/i;
const RE_COUNTRY_CODE = /^[A-Za-z]{2}$/;
const RE_IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const RE_IPV6_CHARS = /^[A-Fa-f0-9:]+$/;
const RE_SAFE_PATH = /^[\w.-]+$/;  // Allow dots for domain paths

// Fallback Sets for O(1) membership lookups (used when index doesn't provide them)
const DEFAULT_PLATFORMS = Object.freeze(['linux', 'freebsd', 'windows', 'darwin', 'openbsd', 'netbsd', 'sunos']);
const DEFAULT_FLAGS = Object.freeze(['authority', 'badexit', 'exit', 'fast', 'guard', 'hsdir', 'named', 'running', 'stable', 'v2dir', 'valid']);

// Country name aliases for common variations
const COUNTRY_ALIASES = Object.freeze({
  'united states': 'us',
  'usa': 'us',
  'uk': 'gb',
  'united kingdom': 'gb',
  'great britain': 'gb',
  'britain': 'gb',
  'england': 'gb',
  'holland': 'nl',
  'the netherlands': 'nl',
  'czech republic': 'cz',
  'czechia': 'cz',
  'south korea': 'kr',
  'korea': 'kr',
  'russia': 'ru',
  'russian federation': 'ru',
});

// Path prefixes for redirect validation (Array - we need startsWith, not Set membership)
const SAFE_REDIRECT_PREFIXES = Object.freeze(['/relay/', '/family/', '/contact/', '/as/', '/country/', '/platform/', '/flag/', '/first_seen/']);

// Precomputed frozen headers object (reused for all HTML responses)
const RESPONSE_HEADERS = Object.freeze({
  'Content-Type': CONTENT_TYPE_HTML,
  ...SECURITY_HEADERS_HTML,
});

// Result type to URL path segment (DRY: single source of truth)
// Empty string = ID is the full path (e.g., aroi domain "1aeo.com" → /1aeo.com/)
const RESULT_TYPE_PATHS = Object.freeze({
  relay: 'relay',
  family: 'family',
  contact: 'contact',
  aroi: '',  // Domain IS the path: /{domain}/
  as: 'as',
  country: 'country',
  platform: 'platform',
  flag: 'flag',
});

// Error codes for detailed diagnostics
const ERR = Object.freeze({
  INDEX_404: 'INDEX_404',
  INDEX_HTTP: 'INDEX_HTTP',
  INDEX_JSON: 'INDEX_JSON',
  INDEX_SCHEMA: 'INDEX_SCHEMA',
  UNKNOWN: 'UNKNOWN',
});

// Helper: create error with code and details
function searchError(code, message, details) {
  const err = new Error(message);
  err.code = code;
  err.details = details;
  return err;
}

// =============================================================================
// HTML TEMPLATES (self-contained, no external CSS dependencies)
// =============================================================================

const HTML_HEAD_START = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>`;

// Self-contained CSS - no Bootstrap dependency
const HTML_HEAD_END = ` - Allium</title>
<style>
*, *::before, *::after { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.6;
  color: #212529;
  background: #fff;
  padding: 40px 20px;
  max-width: 800px;
  margin: 0 auto;
}
h2, h4 { margin: 0 0 1rem; color: #333; }
a { color: #0066cc; } a:hover { color: #004499; }
code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
ul { padding-left: 1.5rem; } li { margin-bottom: 0.5rem; }
.search-box { margin-bottom: 30px; }
.input-group { display: flex; gap: 8px; }
.form-control {
  flex: 1;
  padding: 10px 14px;
  font-size: 1rem;
  border: 1px solid #ced4da;
  border-radius: 4px;
  outline: none;
}
.form-control:focus { border-color: #0066cc; box-shadow: 0 0 0 2px rgba(0,102,204,0.15); }
.btn {
  padding: 10px 20px;
  font-size: 1rem;
  font-weight: 500;
  color: #fff;
  background: #0066cc;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}
.btn:hover { background: #0052a3; }
.results { margin-top: 20px; }
.result-item {
  padding: 12px;
  border-bottom: 1px solid #e9ecef;
  transition: background 0.15s;
}
.result-item:hover { background: #f8f9fa; }
.result-item a { text-decoration: none; color: inherit; } .result-item strong { color: #212529; }
.fp { font-family: "SF Mono", Monaco, "Cascadia Code", monospace; font-size: 0.85em; color: #6c757d; display: block; margin-top: 2px; }
.aroi { font-size: 0.85em; color: #198754; font-weight: 500; text-decoration: none; } .aroi:hover { text-decoration: underline; }
.hint { color: #6c757d; font-style: italic; margin-bottom: 15px; } .text-danger { color: #dc3545; }
.back { margin: 0 0 16px 0; } .back a { color: #6c757d; text-decoration: none; } .back a:hover { color: #0066cc; }
</style>
</head>
<body>
`;

const HTML_FORM_START = `<div class="search-box">
<form action="/search" method="get">
<div class="input-group">
<input type="text" name="q" class="form-control" placeholder="Search by fingerprint, nickname, AS, country, IP..." value="`;

const HTML_FORM_END = `" maxlength="${MAX_QUERY_LENGTH}" autofocus>
<button class="btn" type="submit">Search</button>
</div>
</form>
</div>
`;

const HTML_FOOTER = `<p class="back"><a href="/">← Back to home</a></p>
</body>
</html>`;

const HTML_TIPS = `<h4>Search Tips</h4>
<ul>
<li><strong>Fingerprint:</strong> 6+ hex characters (e.g., <code>ABCD1234</code>)</li>
<li><strong>Nickname:</strong> Relay name (e.g., <code>MyRelay</code>)</li>
<li><strong>AS Number:</strong> With or without prefix (e.g., <code>AS24940</code> or <code>24940</code>)</li>
<li><strong>Country:</strong> Code or name (e.g., <code>de</code> or <code>Germany</code>)</li>
<li><strong>IP Address:</strong> IPv4 or IPv6</li>
<li><strong>Contact:</strong> AROI domain (e.g., <code>example.org</code>)</li>
</ul>
`;

// =============================================================================
// INDEX CACHE WITH PRECOMPUTED LOOKUP MAPS
// =============================================================================

let cachedIndex = null;
let cacheExpiry = 0;

/**
 * Build optimized lookup structures from raw index.
 * Single pass over each array for efficiency.
 * 
 * Schema: Allium v1.3 search-index.json
 *   - relays: [{f, n, a, c, as, cc, ip, fam}]
 *   - families: [{id, sz, nn, px, pxg, a, c, as, cc, fs}]
 *   - lookups: {as_names, country_names, platforms, flags}
 * 
 * @param {object} raw - Raw index data from search-index.json
 * @returns {object} Frozen lookup structure
 * @throws {Error} If index format is invalid
 */
function buildLookupMaps(raw) {
  // Schema validation
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid index format: expected object');
  }
  
  const relays = Array.isArray(raw.relays) ? raw.relays : [];
  const families = Array.isArray(raw.families) ? raw.families : [];
  const lookups = raw.lookups || {};
  
  // O(1) lookup maps
  const fpMap = new Map();
  const nickMultiMap = new Map();  // lowercase nickname -> [relays] (for disambiguation)
  const ipMap = new Map();
  const asSet = new Set();
  const asNameMap = new Map();
  const ccSet = new Set();
  const ccNameMap = new Map();
  const contactDomainMap = new Map();
  const contactDomainPrefixMap = new Map();
  const contactHashMap = new Map();
  const familyIdMap = new Map();
  const familyPrefixMap = new Map();
  const familyNickMap = new Map();
  
  // Helper: extract domain prefix (e.g., "1aeo.com" -> "1aeo")
  const getDomainPrefix = (domain) => {
    const dotIdx = domain.indexOf('.');
    return dotIdx > 0 ? domain.slice(0, dotIdx) : null;
  };
  
  // Precomputed lowercase nicknames for efficient scanning
  const nickLower = new Array(relays.length);

  // Single pass over relays
  for (let i = 0; i < relays.length; i++) {
    const r = relays[i];
    nickLower[i] = r.n ? r.n.toLowerCase() : '';
    
    if (r.f) fpMap.set(r.f, r);
    if (r.n) {
      const nLow = nickLower[i];
      if (!nickMultiMap.has(nLow)) nickMultiMap.set(nLow, []);
      nickMultiMap.get(nLow).push(r);
    }
    if (r.as) asSet.add(r.as.toUpperCase());
    if (r.cc) ccSet.add(r.cc.toLowerCase());
    if (r.ip) {
      const ips = Array.isArray(r.ip) ? r.ip : [r.ip];
      for (let j = 0; j < ips.length; j++) ipMap.set(ips[j], r);
    }
    if (r.a && r.c) {
      const domainLow = r.a.toLowerCase();
      const contact = { domain: r.a, hash: r.c };  // Store both, domain is primary
      contactDomainMap.set(domainLow, contact);
      contactHashMap.set(r.c.toLowerCase(), contact);
      const prefix = getDomainPrefix(domainLow);
      if (prefix && !contactDomainPrefixMap.has(prefix)) {
        contactDomainPrefixMap.set(prefix, contact);
      }
    }
  }

  // Process families
  for (let i = 0; i < families.length; i++) {
    const f = families[i];
    if (f.id) familyIdMap.set(f.id, f);
    if (f.px && !f.pxg) familyPrefixMap.set(f.px.toLowerCase(), f);
    if (f.nn && typeof f.nn === 'object') {
      for (const nickLow of Object.keys(f.nn)) {
        if (!familyNickMap.has(nickLow)) familyNickMap.set(nickLow, f);
      }
    }
    if (f.a && f.c && Array.isArray(f.c) && f.c.length > 0) {
      const domainLow = f.a.toLowerCase();
      const contact = { domain: f.a, hash: f.c[0] };  // Store both, domain is primary
      contactDomainMap.set(domainLow, contact);
      for (const hash of f.c) contactHashMap.set(hash.toLowerCase(), contact);
      const prefix = getDomainPrefix(domainLow);
      if (prefix && !contactDomainPrefixMap.has(prefix)) {
        contactDomainPrefixMap.set(prefix, contact);
      }
    }
  }

  // AS names from lookups
  for (const [asNum, asName] of Object.entries(lookups.as_names || {})) {
    const norm = asNum.toUpperCase();
    asSet.add(norm);
    asNameMap.set(norm, asName);
  }

  // Country names from lookups
  for (const [code, name] of Object.entries(lookups.country_names || {})) {
    const codeLow = code.toLowerCase();
    ccSet.add(codeLow);
    ccNameMap.set(name.toLowerCase(), codeLow);
  }
  
  // Platforms/flags from lookups or defaults
  const platformSet = new Set((lookups.platforms || DEFAULT_PLATFORMS).map(p => p.toLowerCase()));
  const flagSet = new Set((lookups.flags || DEFAULT_FLAGS).map(f => f.toLowerCase()));

  return Object.freeze({
    relays, families, nickLower, fpMap, nickMultiMap, ipMap,
    asSet, asNameMap, ccSet, ccNameMap,
    contactDomainMap, contactDomainPrefixMap, contactHashMap,
    familyIdMap, familyPrefixMap, familyNickMap, platformSet, flagSet,
  });
}

async function loadIndex(origin) {
  const now = Date.now();
  if (cachedIndex && now < cacheExpiry) return cachedIndex;
  
  let res;
  try {
    res = await fetch(`${origin}/search-index.json`, {
      cf: { cacheTtl: 300, cacheEverything: true },
    });
  } catch (e) {
    throw searchError(ERR.INDEX_HTTP, 'Network error fetching index', e.message);
  }
  
  if (res.status === 404) {
    throw searchError(ERR.INDEX_404, 'search-index.json not found (HTTP 404)',
      'Index file missing. Site may be updating or allium failed to generate it.');
  }
  if (!res.ok) {
    throw searchError(ERR.INDEX_HTTP, `Index fetch failed (HTTP ${res.status})`,
      `Server returned ${res.status} ${res.statusText || ''}.`);
  }
  
  let raw;
  try {
    raw = await res.json();
  } catch (e) {
    throw searchError(ERR.INDEX_JSON, 'Failed to parse index as JSON',
      `${e.message}. File may be corrupted or truncated.`);
  }
  
  try {
    cachedIndex = buildLookupMaps(raw);
  } catch (e) {
    throw searchError(ERR.INDEX_SCHEMA, 'Index schema validation failed',
      `${e.message}. Index version may not match search function.`);
  }
  
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
  return new Response(body, { status, headers: RESPONSE_HEADERS });
}

function safeRedirect(origin, path) {
  // Validate against prefix allowlist OR domain-style path (e.g., /1aeo.com/)
  let ok = false;
  for (let i = 0; i < SAFE_REDIRECT_PREFIXES.length; i++) {
    if (path.startsWith(SAFE_REDIRECT_PREFIXES[i])) { ok = true; break; }
  }
  // Allow domain-style paths: /domain.tld/ (must have dot, validated by RE_SAFE_PATH)
  if (!ok && path.includes('.') && /^\/[\w.-]+\/$/.test(path)) ok = true;
  if (!ok || path.includes('://') || path.startsWith('//')) {
    console.error('Blocked redirect:', path);
    return new Response('Invalid redirect', { status: 400 });
  }
  return Response.redirect(new URL(path, origin).href, 302);
}

function handleError(err, query) {
  console.error('Search error:', {
    code: err.code || ERR.UNKNOWN,
    message: err.message,
    details: err.details,
    query: query?.slice(0, 50),
  });
  return renderError(err, query);
}

// =============================================================================
// SEARCH LOGIC
// =============================================================================

/**
 * Map relay to result format for disambiguation.
 */
function relayResult(r) {
  return { t: 'relay', f: r.f, n: r.n, cc: r.cc, a: r.a || null, c: r.c || null };
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

  // 4. Country code - O(1) Set lookup (return UPPERCASE for URL paths)
  if (RE_COUNTRY_CODE.test(q) && idx.ccSet.has(qLow)) {
    return { type: 'country', id: qLow.toUpperCase() };
  }

  // 5. Country name - O(1) Map lookup
  const ccByName = idx.ccNameMap.get(qLow);
  if (ccByName) return { type: 'country', id: ccByName.toUpperCase() };

  // 5b. Country aliases (e.g., "united states" -> "us", "uk" -> "gb")
  const ccByAlias = COUNTRY_ALIASES[qLow];
  if (ccByAlias) return { type: 'country', id: ccByAlias.toUpperCase() };

  // 6. Platform - O(1) Set lookup (dynamic from index or fallback)
  if (idx.platformSet.has(qLow)) return { type: 'platform', id: qLow };

  // 7. Flag - O(1) Set lookup (dynamic from index or fallback)
  if (idx.flagSet.has(qLow)) return { type: 'flag', id: qLow };

  // 8. Contact domain/hash - O(1) Map lookups → redirect to /{domain}/ (fallback: /contact/{hash}/)
  const cDomain = idx.contactDomainMap.get(qLow);
  if (cDomain) return { type: 'aroi', id: cDomain.domain, fallback: cDomain.hash };
  const cHash = idx.contactHashMap.get(qLow);
  if (cHash) return { type: 'aroi', id: cHash.domain, fallback: cHash.hash };
  
  // 8b. Contact domain prefix (e.g., "1aeo" → /1aeo.com/, "prsv" → /prsv.ch/)
  const cDomainPrefix = idx.contactDomainPrefixMap.get(qLow);
  if (cDomainPrefix) return { type: 'aroi', id: cDomainPrefix.domain, fallback: cDomainPrefix.hash };

  // 9. IP address - O(1) Map lookup
  if (RE_IPV4.test(q) || (q.includes(':') && RE_IPV6_CHARS.test(q))) {
    const relay = idx.ipMap.get(q);
    if (relay) return { type: 'relay', id: relay.f };
  }

  // 10. Exact nickname - O(1) Map lookup with disambiguation for duplicates
  const exactNickMatches = idx.nickMultiMap.get(qLow);
  if (exactNickMatches) {
    if (exactNickMatches.length === 1) {
      return { type: 'relay', id: exactNickMatches[0].f };
    }
    // Multiple relays with same nickname - show disambiguation
    return { 
      type: 'multiple', 
      matches: exactNickMatches.slice(0, MAX_RESULTS).map(relayResult), 
      hint: `${exactNickMatches.length} relays named "${q}"` 
    };
  }

  // 11. Family prefix - O(1) Map lookup (non-generic prefixes only)
  const famByPrefix = idx.familyPrefixMap.get(qLow);
  if (famByPrefix) return { type: 'family', id: famByPrefix.id };

  // 12. Family nickname - O(1) Map lookup (from nn dict, keys already lowercase)
  const famByNick = idx.familyNickMap.get(qLow);
  if (famByNick) return { type: 'family', id: famByNick.id };

  // 13. Nickname prefix/contains - Combined single pass with precomputed lowercase
  const prefixMatches = [];
  const containsMatches = [];
  const relays = idx.relays;
  const nickLower = idx.nickLower;  // Precomputed lowercase nicknames
  const maxContains = MAX_RESULTS * 2;
  
  for (let i = 0; i < relays.length; i++) {
    const nLow = nickLower[i];
    if (!nLow) continue;
    
    if (nLow.startsWith(qLow)) {
      prefixMatches.push(relays[i]);
      // Early exit: enough prefix matches found
      if (prefixMatches.length > MAX_RESULTS) break;
    } else if (containsMatches.length <= maxContains && nLow.includes(qLow)) {
      containsMatches.push(relays[i]);
    }
    
    // Early exit: have enough of both types
    if (prefixMatches.length >= MAX_RESULTS && containsMatches.length >= maxContains) break;
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
    '<p class="back"><a href="/">← Back to home</a></p>\n' +
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
      // Show AROI as link: /{domain}/ primary, /contact/{hash}/ fallback
      const aroiHref = m.a ? `/${escapeHtml(m.a)}/` : (m.c ? `/contact/${escapeHtml(m.c)}/` : null);
      const aroi = aroiHref ? ` · <a href="${aroiHref}" class="aroi">${escapeHtml(m.a || m.c)}</a>` : '';
      content += `<div class="result-item"><a href="/relay/${fp}/"><strong>${name}</strong></a>${aroi}<a href="/relay/${fp}/" class="fp">${cc}${fp}</a></div>\n`;
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

function renderError(err, query) {
  const code = err.code || ERR.UNKNOWN;
  const message = err.message || 'Unknown error';
  const details = err.details || '';
  const timestamp = new Date().toISOString();
  
  const content = 
    `<p><strong>Error ${escapeHtml(code)}:</strong> ${escapeHtml(message)}</p>\n` +
    (details ? `<p>${escapeHtml(details)}</p>\n` : '') +
    `<p class="hint">Timestamp: ${timestamp}</p>\n` +
    `<p class="hint">If this persists, try again in a few minutes.</p>\n`;
  
  return htmlResponse(renderPage('Search Error', content, query), 503);
}

// =============================================================================
// AROI DOMAIN VALIDATION HELPERS
// =============================================================================

/**
 * Check if an AROI domain page exists in R2 storage.
 * Returns true if the page exists, false otherwise.
 * 
 * @param {object} env - Environment bindings
 * @param {string} domain - AROI domain (e.g., "1aeo.com")
 * @returns {Promise<boolean>}
 */
async function aroiPageExistsInR2(env, domain) {
  if (!env?.METRICS_CONTENT) return null; // R2 not configured
  
  try {
    // Check for /{domain}/index.html
    const object = await env.METRICS_CONTENT.get(`${domain}/index.html`);
    return object !== null;
  } catch (e) {
    console.error(`R2 AROI check error for ${domain}:`, e.message);
    return null; // Unknown, treat as not verified
  }
}

/**
 * Check if an AROI domain page exists in DO Spaces.
 * Returns true if the page exists, false otherwise.
 * 
 * @param {object} env - Environment bindings
 * @param {string} domain - AROI domain (e.g., "1aeo.com")
 * @returns {Promise<boolean>}
 */
async function aroiPageExistsInSpaces(env, domain) {
  const baseUrl = env?.DO_SPACES_URL;
  if (!baseUrl) return null; // DO Spaces not configured
  
  try {
    const url = `${baseUrl.replace(/\/$/, '')}/${domain}/index.html`;
    const response = await fetch(url, {
      method: 'HEAD',
      headers: { 'User-Agent': 'Cloudflare-Pages/1.0' },
    });
    return response.ok;
  } catch (e) {
    console.error(`DO Spaces AROI check error for ${domain}:`, e.message);
    return null; // Unknown, treat as not verified
  }
}

/**
 * Check if an AROI domain is validated (has a page generated).
 * Checks storage backends in configured order.
 * 
 * For validated AROI domains, redirect to /{domain}/
 * For unvalidated/misconfigured domains, redirect to /contact/{hash}/
 * 
 * @param {object} env - Environment bindings  
 * @param {string} domain - AROI domain to check
 * @returns {Promise<boolean>} true if validated, false if not
 */
async function isAroiDomainValidated(env, domain) {
  // Parse storage order from env
  const orderStr = env?.STORAGE_ORDER || 'r2,do,failover';
  const order = orderStr.split(',').map(s => s.trim().toLowerCase());
  
  for (const backend of order) {
    let result = null;
    
    if (backend === 'r2') {
      result = await aroiPageExistsInR2(env, domain);
    } else if (backend === 'do') {
      result = await aroiPageExistsInSpaces(env, domain);
    }
    // Skip 'failover' - we don't check failover for AROI validation
    
    // If we got a definitive answer (true or false), return it
    if (result === true) return true;
    if (result === false) return false;
    // result === null means backend not configured or error, try next
  }
  
  // No backend could verify, assume not validated (use hash fallback)
  return false;
}

// =============================================================================
// REQUEST HANDLER
// =============================================================================

export async function onRequest(ctx) {
  // Only handle GET and HEAD requests
  if (ctx.request.method !== 'GET' && ctx.request.method !== 'HEAD') {
    return new Response('Method not allowed', { status: 405 });
  }
  
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
    if (pathType !== undefined && result.id) {
      if (!isSafePath(result.id)) {
        // Fallback to hash-based URL if domain path is invalid
        if (result.fallback && isSafePath(result.fallback)) {
          return safeRedirect(url.origin, `/contact/${result.fallback}/`);
        }
        return handleError(new Error('Invalid ID'), q);
      }
      
      // For AROI domains, verify the domain page exists before redirecting
      // If domain is not validated (misconfigured), use contact hash fallback
      if (result.type === 'aroi' && result.fallback) {
        const isValidated = await isAroiDomainValidated(ctx.env, result.id);
        if (!isValidated) {
          // Domain not validated, redirect to contact hash instead
          if (isSafePath(result.fallback)) {
            return safeRedirect(url.origin, `/contact/${result.fallback}/`);
          }
        }
      }
      
      // Empty pathType means ID is the full path (e.g., aroi: /1aeo.com/)
      const path = pathType ? `/${pathType}/${result.id}/` : `/${result.id}/`;
      return safeRedirect(url.origin, path);
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
