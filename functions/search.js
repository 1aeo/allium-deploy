/**
 * Cloudflare Pages Function - Search Handler
 * 
 * Handles /search?q=... requests, searches the static search-index.json,
 * and returns redirects or disambiguation/not-found pages.
 * 
 * Query Types Supported:
 *   - Fingerprint (full 40 hex chars or partial 6-39 hex chars)
 *   - Nickname (relay name)
 *   - AROI Domain (operator contact)
 *   - AS Number (AS12345 or 12345)
 *   - Country (code like 'de' or name like 'Germany')
 *   - IP Address (IPv4 or IPv6)
 *   - Platform (linux, freebsd, windows)
 *   - Flag (exit, guard, stable)
 *   - Family prefix (common nickname prefix)
 * 
 * Security Features:
 *   - Input validation (length limit, character allowlist)
 *   - XSS prevention (HTML escaping)
 *   - Open redirect prevention (path allowlist)
 *   - Security headers (CSP, X-Frame-Options, etc.)
 *   - ReDoS-safe regex patterns
 *   - Generic error messages (no internal details exposed)
 */

// =============================================================================
// CONSTANTS
// =============================================================================

const MAX_QUERY_LENGTH = 100;
const INDEX_CACHE_TTL = 300; // 5 minutes

// Character allowlist for queries (alphanumeric, dot, colon, hyphen, underscore, space)
const ALLOWED_CHARS_REGEX = /^[\w\s.\-:@]+$/;

// ReDoS-safe patterns (all O(n) complexity)
const PATTERNS = {
  FULL_FINGERPRINT: /^[A-Fa-f0-9]{40}$/,
  PARTIAL_FINGERPRINT: /^[A-Fa-f0-9]{6,39}$/,
  HEX_STRING: /^[A-Fa-f0-9]+$/,
  AS_NUMBER: /^(?:AS)?(\d{1,10})$/i,
  COUNTRY_CODE: /^[A-Za-z]{2}$/,
  // IPv4: simple digit and dot pattern
  IPV4: /^(?:\d{1,3}\.){3}\d{1,3}$/,
  // IPv6: hex and colon pattern (simplified, catches most formats)
  IPV6: /^[A-Fa-f0-9:]+$/,
  // Safe path segment: alphanumeric, hyphen, underscore only
  SAFE_PATH: /^[\w-]+$/,
};

// Valid redirect path prefixes (allowlist for open redirect prevention)
const SAFE_REDIRECT_PREFIXES = [
  '/relay/',
  '/family/',
  '/contact/',
  '/as/',
  '/country/',
  '/platform/',
  '/flag/',
  '/first_seen/',
];

// Security headers for HTML responses
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': [
    "default-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "script-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
  ].join('; '),
};

// Known platforms and flags (lowercase for comparison)
const KNOWN_PLATFORMS = ['linux', 'freebsd', 'windows', 'darwin', 'openbsd', 'netbsd', 'sunos'];
const KNOWN_FLAGS = ['authority', 'badexit', 'exit', 'fast', 'guard', 'hsdir', 'named', 'running', 'stable', 'v2dir', 'valid'];

// =============================================================================
// INDEX CACHE
// =============================================================================

let indexCache = null;
let indexCacheTime = 0;

/**
 * Load and cache the search index.
 * Fetches from the static /search-index.json file.
 * 
 * @param {string} origin - The request origin URL
 * @returns {Promise<Object>} The parsed search index
 */
async function loadIndex(origin) {
  const now = Date.now();
  
  // Return cached index if still valid
  if (indexCache && (now - indexCacheTime) < INDEX_CACHE_TTL * 1000) {
    return indexCache;
  }
  
  const indexUrl = `${origin}/search-index.json`;
  const response = await fetch(indexUrl, {
    cf: { cacheTtl: INDEX_CACHE_TTL, cacheEverything: true },
  });
  
  if (!response.ok) {
    throw new Error(`Failed to load search index: ${response.status}`);
  }
  
  indexCache = await response.json();
  indexCacheTime = now;
  
  return indexCache;
}

// =============================================================================
// INPUT VALIDATION & SANITIZATION
// =============================================================================

/**
 * Sanitize and validate user input.
 * Returns { valid: boolean, sanitized: string, error: string }
 * 
 * @param {string|null} rawQuery - Raw query string from URL
 * @returns {Object} Validation result
 */
function sanitizeQuery(rawQuery) {
  // Empty/null check
  if (!rawQuery || typeof rawQuery !== 'string') {
    return { valid: false, sanitized: '', error: 'Query is required' };
  }
  
  // Trim whitespace
  const trimmed = rawQuery.trim();
  
  if (!trimmed) {
    return { valid: false, sanitized: '', error: 'Query is required' };
  }
  
  // Length check
  if (trimmed.length > MAX_QUERY_LENGTH) {
    return {
      valid: false,
      sanitized: '',
      error: `Query too long (max ${MAX_QUERY_LENGTH} characters)`,
    };
  }
  
  // Character allowlist check
  if (!ALLOWED_CHARS_REGEX.test(trimmed)) {
    return {
      valid: false,
      sanitized: '',
      error: 'Query contains invalid characters',
    };
  }
  
  return { valid: true, sanitized: trimmed, error: '' };
}

/**
 * Check if a string is safe for use in URL paths.
 * 
 * @param {string} segment - Path segment to validate
 * @returns {boolean} Whether the segment is safe
 */
function isSafePathSegment(segment) {
  if (!segment || typeof segment !== 'string') return false;
  if (segment.length > 100) return false;
  // Allow fingerprints (hex), AS numbers, country codes, etc.
  return /^[\w-]+$/.test(segment);
}

// =============================================================================
// HTML ESCAPING (XSS Prevention)
// =============================================================================

/**
 * Escape HTML special characters to prevent XSS.
 * 
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Escape string for use in HTML attributes.
 * 
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
function escapeAttr(str) {
  return escapeHtml(str);
}

// =============================================================================
// SAFE REDIRECTS
// =============================================================================

/**
 * Create a safe redirect response.
 * Validates the path against an allowlist to prevent open redirects.
 * 
 * @param {string} origin - Request origin URL
 * @param {string} path - Redirect path (must start with /)
 * @returns {Response} Redirect response or 400 error
 */
function safeRedirect(origin, path) {
  // Validate path starts with allowed prefix
  const isAllowed = SAFE_REDIRECT_PREFIXES.some(prefix => path.startsWith(prefix));
  
  if (!isAllowed) {
    console.error(`Blocked unsafe redirect: ${path}`);
    return new Response('Invalid redirect', { status: 400 });
  }
  
  // Prevent protocol injection (//evil.com or javascript:)
  if (path.includes('://') || path.startsWith('//') || path.toLowerCase().startsWith('javascript:')) {
    console.error(`Blocked protocol in redirect: ${path}`);
    return new Response('Invalid redirect', { status: 400 });
  }
  
  // Construct full URL with validated origin
  const fullUrl = new URL(path, origin).toString();
  
  return Response.redirect(fullUrl, 302);
}

// =============================================================================
// SECURE RESPONSE HELPERS
// =============================================================================

/**
 * Create a response with security headers.
 * 
 * @param {string} body - Response body (HTML)
 * @param {number} status - HTTP status code
 * @param {Object} additionalHeaders - Additional headers to merge
 * @returns {Response} Response with security headers
 */
function secureResponse(body, status = 200, additionalHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      ...SECURITY_HEADERS,
      ...additionalHeaders,
    },
  });
}

/**
 * Handle errors securely without exposing internal details.
 * 
 * @param {Error} error - The caught error
 * @param {string} query - The user's query (for logging)
 * @returns {Response} User-safe error response
 */
function handleError(error, query) {
  // Log full error server-side for debugging
  console.error('Search error:', {
    message: error.message,
    stack: error.stack,
    query: query?.substring(0, 50),
  });
  
  // Return generic message to user
  return secureResponse(renderErrorPage(), 503);
}

// =============================================================================
// SEARCH LOGIC
// =============================================================================

/**
 * Perform search against the index.
 * Returns a result object with type and match data.
 * 
 * @param {string} query - Sanitized search query
 * @param {Object} index - The search index
 * @returns {Object} Search result
 */
function search(query, index) {
  const q = query.trim();
  const qLower = q.toLowerCase();
  
  // 1. Check for exact fingerprint (40 hex chars)
  if (PATTERNS.FULL_FINGERPRINT.test(q)) {
    const fp = q.toUpperCase();
    const relay = index.relays?.find(r => r.f === fp);
    if (relay) {
      return { type: 'relay', fingerprint: relay.f };
    }
    // Check if it's a family fingerprint
    const family = index.families?.find(f => f.id === fp);
    if (family) {
      return { type: 'family', familyId: family.id };
    }
    return { type: 'not_found' };
  }
  
  // 2. Check for partial fingerprint (6-39 hex chars)
  if (PATTERNS.PARTIAL_FINGERPRINT.test(q)) {
    const prefix = q.toUpperCase();
    const matches = index.relays?.filter(r => r.f.startsWith(prefix)) || [];
    
    if (matches.length === 1) {
      return { type: 'relay', fingerprint: matches[0].f };
    }
    if (matches.length > 1) {
      return {
        type: 'multiple',
        matches: matches.slice(0, 20).map(r => ({
          type: 'relay',
          fingerprint: r.f,
          nickname: r.n,
        })),
        hint: 'Multiple relays match this fingerprint prefix',
      };
    }
    // Continue to other checks if no fingerprint match
  }
  
  // 3. Check for AS number
  const asMatch = q.match(PATTERNS.AS_NUMBER);
  if (asMatch) {
    const asNum = asMatch[1];
    const asEntry = index.autonomous_systems?.find(a => a.num === asNum || a.num === `AS${asNum}`);
    if (asEntry) {
      return { type: 'as', asNumber: asEntry.num.replace(/^AS/i, 'AS') };
    }
    // Check if any relay has this AS
    const asRelays = index.relays?.filter(r => r.as === `AS${asNum}` || r.as === asNum) || [];
    if (asRelays.length > 0) {
      return { type: 'as', asNumber: `AS${asNum}` };
    }
  }
  
  // 4. Check for country code (2 letters)
  if (PATTERNS.COUNTRY_CODE.test(q)) {
    const cc = qLower;
    const country = index.countries?.find(c => c.code?.toLowerCase() === cc);
    if (country) {
      return { type: 'country', countryCode: country.code.toLowerCase() };
    }
    // Check if any relay has this country
    const ccRelays = index.relays?.filter(r => r.cc?.toLowerCase() === cc) || [];
    if (ccRelays.length > 0) {
      return { type: 'country', countryCode: cc };
    }
  }
  
  // 5. Check for country name
  const countryByName = index.countries?.find(c => c.name?.toLowerCase() === qLower);
  if (countryByName) {
    return { type: 'country', countryCode: countryByName.code.toLowerCase() };
  }
  
  // 6. Check for IP address
  if (PATTERNS.IPV4.test(q) || (q.includes(':') && PATTERNS.IPV6.test(q))) {
    const relay = index.relays?.find(r => r.ip?.includes(q));
    if (relay) {
      return { type: 'relay', fingerprint: relay.f };
    }
  }
  
  // 7. Check for platform
  if (KNOWN_PLATFORMS.includes(qLower)) {
    return { type: 'platform', platform: qLower };
  }
  
  // 8. Check for flag
  if (KNOWN_FLAGS.includes(qLower)) {
    return { type: 'flag', flag: qLower };
  }
  
  // 9. Check for contact/AROI domain
  const contactMatch = index.contacts?.find(c => 
    c.domain?.toLowerCase() === qLower || 
    c.hash?.toLowerCase() === qLower
  );
  if (contactMatch) {
    return { type: 'contact', contactMd5: contactMatch.hash };
  }
  
  // Check if query looks like a domain
  if (q.includes('.') && !PATTERNS.IPV4.test(q)) {
    const domainMatch = index.contacts?.find(c => c.domain?.toLowerCase() === qLower);
    if (domainMatch) {
      return { type: 'contact', contactMd5: domainMatch.hash };
    }
  }
  
  // 10. Check for exact nickname match
  const exactNickname = index.relays?.find(r => r.n?.toLowerCase() === qLower);
  if (exactNickname) {
    return { type: 'relay', fingerprint: exactNickname.f };
  }
  
  // 11. Check for nickname prefix (family pattern)
  const nicknameMatches = index.relays?.filter(r => 
    r.n?.toLowerCase().startsWith(qLower)
  ) || [];
  
  if (nicknameMatches.length === 1) {
    return { type: 'relay', fingerprint: nicknameMatches[0].f };
  }
  
  if (nicknameMatches.length > 1) {
    // Check if they share a family
    const familyIds = new Set(nicknameMatches.map(r => r.fam).filter(Boolean));
    
    if (familyIds.size === 1) {
      const familyId = familyIds.values().next().value;
      return { type: 'family', familyId };
    }
    
    return {
      type: 'multiple',
      matches: nicknameMatches.slice(0, 20).map(r => ({
        type: 'relay',
        fingerprint: r.f,
        nickname: r.n,
        country: r.cc,
      })),
      hint: `Multiple relays match "${escapeHtml(q)}"`,
    };
  }
  
  // 12. Check for family by member nickname or fingerprint
  if (index.families) {
    const familyMatch = index.families.find(f => 
      f.members?.some(m => m.toLowerCase() === qLower) ||
      f.prefix?.toLowerCase() === qLower
    );
    if (familyMatch) {
      return { type: 'family', familyId: familyMatch.id };
    }
  }
  
  // 13. Partial nickname search (contains)
  const partialMatches = index.relays?.filter(r => 
    r.n?.toLowerCase().includes(qLower)
  ) || [];
  
  if (partialMatches.length === 1) {
    return { type: 'relay', fingerprint: partialMatches[0].f };
  }
  
  if (partialMatches.length > 1 && partialMatches.length <= 50) {
    return {
      type: 'multiple',
      matches: partialMatches.slice(0, 20).map(r => ({
        type: 'relay',
        fingerprint: r.f,
        nickname: r.n,
        country: r.cc,
      })),
      hint: `Found ${partialMatches.length} relays containing "${escapeHtml(q)}"`,
    };
  }
  
  // Nothing found
  return { type: 'not_found' };
}

// =============================================================================
// PAGE RENDERING
// =============================================================================

/**
 * Common HTML head with styles.
 * 
 * @param {string} title - Page title
 * @returns {string} HTML head section
 */
function renderHead(title) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - Allium</title>
  <link rel="stylesheet" href="/static/css/bootstrap.min.css">
  <style>
    body { padding: 40px 20px; max-width: 800px; margin: 0 auto; }
    .search-box { margin-bottom: 30px; }
    .results { margin-top: 20px; }
    .result-item { padding: 10px; border-bottom: 1px solid #eee; }
    .result-item:hover { background: #f8f9fa; }
    .result-item a { text-decoration: none; }
    .fingerprint { font-family: monospace; font-size: 0.85em; color: #666; }
    .country-flag { margin-right: 5px; }
    .hint { color: #666; font-style: italic; margin-bottom: 15px; }
    .back-link { margin-top: 20px; }
  </style>
</head>`;
}

/**
 * Render search form HTML.
 * 
 * @param {string} currentQuery - Current query value
 * @returns {string} Search form HTML
 */
function renderSearchForm(currentQuery = '') {
  return `
  <div class="search-box">
    <form action="/search" method="get">
      <div class="input-group">
        <input type="text" name="q" class="form-control" 
               placeholder="Search by fingerprint, nickname, AS, country, IP..." 
               value="${escapeAttr(currentQuery)}"
               maxlength="${MAX_QUERY_LENGTH}"
               autofocus>
        <button class="btn btn-primary" type="submit">Search</button>
      </div>
    </form>
  </div>`;
}

/**
 * Render disambiguation page for multiple matches.
 * 
 * @param {Array} matches - Array of match objects
 * @param {string} query - Original query
 * @param {string} hint - Hint message
 * @returns {Response} HTML response
 */
function renderDisambiguationPage(matches, query, hint) {
  const matchesHtml = matches.map(match => {
    let href, label, detail;
    
    if (match.type === 'relay') {
      href = `/relay/${escapeAttr(match.fingerprint)}/`;
      label = escapeHtml(match.nickname || 'Unnamed');
      detail = `<span class="fingerprint">${escapeHtml(match.fingerprint)}</span>`;
      if (match.country) {
        detail = `<span class="country-flag">${escapeHtml(match.country.toUpperCase())}</span> ${detail}`;
      }
    } else if (match.type === 'family') {
      href = `/family/${escapeAttr(match.familyId)}/`;
      label = `Family: ${escapeHtml(match.familyId.substring(0, 8))}...`;
      detail = '';
    } else if (match.type === 'contact') {
      href = `/contact/${escapeAttr(match.contactMd5)}/`;
      label = escapeHtml(match.domain || match.contactMd5);
      detail = '';
    } else {
      return '';
    }
    
    return `
    <div class="result-item">
      <a href="${href}">
        <strong>${label}</strong>
        ${detail ? `<br>${detail}` : ''}
      </a>
    </div>`;
  }).join('');
  
  const html = `
${renderHead('Search Results')}
<body>
  <h2>Search Results</h2>
  ${renderSearchForm(query)}
  
  <div class="results">
    ${hint ? `<p class="hint">${escapeHtml(hint)}</p>` : ''}
    ${matchesHtml}
  </div>
  
  <p class="back-link"><a href="/">← Back to home</a></p>
</body>
</html>`;

  return secureResponse(html, 200);
}

/**
 * Render not-found page.
 * 
 * @param {string} query - Original query
 * @returns {Response} HTML response
 */
function renderNotFoundPage(query) {
  const html = `
${renderHead('Not Found')}
<body>
  <h2>No Results Found</h2>
  ${renderSearchForm(query)}
  
  <div class="results">
    <p>No relays, families, or operators found matching "<strong>${escapeHtml(query)}</strong>".</p>
    
    <h4>Search Tips</h4>
    <ul>
      <li><strong>Fingerprint:</strong> Enter 6+ hex characters (e.g., <code>ABCD1234</code>)</li>
      <li><strong>Nickname:</strong> Enter the relay name (e.g., <code>MyRelay</code>)</li>
      <li><strong>AS Number:</strong> Enter with or without prefix (e.g., <code>AS24940</code> or <code>24940</code>)</li>
      <li><strong>Country:</strong> Enter code or name (e.g., <code>de</code> or <code>Germany</code>)</li>
      <li><strong>IP Address:</strong> Enter IPv4 or IPv6 address</li>
      <li><strong>Contact:</strong> Enter AROI domain (e.g., <code>example.org</code>)</li>
    </ul>
  </div>
  
  <p class="back-link"><a href="/">← Back to home</a></p>
</body>
</html>`;

  return secureResponse(html, 404);
}

/**
 * Render error page.
 * 
 * @returns {string} HTML content
 */
function renderErrorPage() {
  return `
${renderHead('Search Error')}
<body>
  <h2>Search Temporarily Unavailable</h2>
  <p>Please try again in a few moments.</p>
  <p class="back-link"><a href="/">← Back to home</a></p>
</body>
</html>`;
}

/**
 * Render invalid query page.
 * 
 * @param {string} error - Error message
 * @returns {Response} HTML response
 */
function renderInvalidQueryPage(error) {
  const html = `
${renderHead('Invalid Search')}
<body>
  <h2>Invalid Search Query</h2>
  ${renderSearchForm('')}
  
  <div class="results">
    <p class="text-danger">${escapeHtml(error)}</p>
  </div>
  
  <p class="back-link"><a href="/">← Back to home</a></p>
</body>
</html>`;

  return secureResponse(html, 400);
}

// =============================================================================
// REQUEST HANDLER
// =============================================================================

/**
 * Main request handler for /search endpoint.
 * 
 * @param {Object} context - Cloudflare Pages Function context
 * @returns {Promise<Response>} HTTP response
 */
export async function onRequestGet(context) {
  const { request } = context;
  const url = new URL(request.url);
  const rawQuery = url.searchParams.get('q');
  
  // Input validation
  const { valid, sanitized, error } = sanitizeQuery(rawQuery);
  
  if (!valid) {
    if (!rawQuery || !rawQuery.trim()) {
      // Empty query - redirect home
      return Response.redirect(url.origin + '/', 302);
    }
    // Invalid query - show error
    return renderInvalidQueryPage(error);
  }
  
  try {
    const index = await loadIndex(url.origin);
    const result = search(sanitized, index);
    
    switch (result.type) {
      case 'relay':
        if (!isSafePathSegment(result.fingerprint)) {
          return handleError(new Error('Invalid fingerprint'), sanitized);
        }
        return safeRedirect(url.origin, `/relay/${result.fingerprint}/`);
      
      case 'family':
        if (!isSafePathSegment(result.familyId)) {
          return handleError(new Error('Invalid family ID'), sanitized);
        }
        return safeRedirect(url.origin, `/family/${result.familyId}/`);
      
      case 'contact':
        if (!isSafePathSegment(result.contactMd5)) {
          return handleError(new Error('Invalid contact hash'), sanitized);
        }
        return safeRedirect(url.origin, `/contact/${result.contactMd5}/`);
      
      case 'as':
        if (!isSafePathSegment(result.asNumber)) {
          return handleError(new Error('Invalid AS number'), sanitized);
        }
        return safeRedirect(url.origin, `/as/${result.asNumber}/`);
      
      case 'country':
        if (!isSafePathSegment(result.countryCode)) {
          return handleError(new Error('Invalid country code'), sanitized);
        }
        return safeRedirect(url.origin, `/country/${result.countryCode}/`);
      
      case 'platform':
        if (!isSafePathSegment(result.platform)) {
          return handleError(new Error('Invalid platform'), sanitized);
        }
        return safeRedirect(url.origin, `/platform/${result.platform}/`);
      
      case 'flag':
        if (!isSafePathSegment(result.flag)) {
          return handleError(new Error('Invalid flag'), sanitized);
        }
        return safeRedirect(url.origin, `/flag/${result.flag}/`);
      
      case 'multiple':
        return renderDisambiguationPage(result.matches, sanitized, result.hint);
      
      case 'not_found':
      default:
        return renderNotFoundPage(sanitized);
    }
  } catch (err) {
    return handleError(err, sanitized);
  }
}
