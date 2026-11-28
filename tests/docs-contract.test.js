import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const skipDirs = new Set(['.git', 'node_modules']);

function read(relPath) {
  return fs.readFileSync(path.join(root, relPath), 'utf8');
}

function stripCode(text) {
  return text
    .replace(/```[\s\S]*?```/g, '')
    .replace(/~~~[\s\S]*?~~~/g, '')
    .replace(/`[^`\n]+`/g, '');
}

function listMarkdownFiles(dir = root) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (skipDirs.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...listMarkdownFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      results.push(full);
    }
  }
  return results.sort();
}

function isEscaped(text, index) {
  let backslashes = 0;
  for (let pos = index - 1; pos >= 0 && text[pos] === '\\'; pos -= 1) {
    backslashes += 1;
  }
  return backslashes % 2 === 1;
}

function normalizeLabel(label) {
  return label.trim().replace(/\s+/g, ' ').toLowerCase();
}

const NAMED_ENTITIES = new Map([
  ['amp', '&'],
  ['lt', '<'],
  ['gt', '>'],
  ['quot', '"'],
  ['apos', "'"],
]);

const DEST_UNESCAPE_RE =
  /\\([!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~])|&#(\d{1,7});|&#[xX]([0-9a-fA-F]{1,6});|&([A-Za-z][A-Za-z0-9]{1,31});/g;

function unescapeDestination(dest) {
  return dest.replace(DEST_UNESCAPE_RE, (full, punct, dec, hex, named) => {
    if (punct) return punct;
    if (dec || hex) {
      const code = Number.parseInt(dec || hex, dec ? 10 : 16);
      if (code === 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
        return '\uFFFD';
      }
      return String.fromCodePoint(code);
    }
    return NAMED_ENTITIES.get(named.toLowerCase()) ?? full;
  });
}

function skipOptionalNewlineSpaces(text, pos) {
  while (pos < text.length && (text[pos] === ' ' || text[pos] === '\t')) pos += 1;
  if (pos < text.length && text[pos] === '\r') pos += 1;
  if (pos < text.length && text[pos] === '\n') {
    pos += 1;
    while (pos < text.length && (text[pos] === ' ' || text[pos] === '\t')) pos += 1;
  }
  return pos;
}

function skipOptionalInlineTitle(text, pos) {
  pos = skipOptionalNewlineSpaces(text, pos);
  if (pos >= text.length || text[pos] === ')') return pos;
  const opener = text[pos];
  if (opener !== '"' && opener !== "'" && opener !== '(') return -1;
  const closer = opener === '(' ? ')' : opener;
  pos += 1;
  while (pos < text.length) {
    const ch = text[pos];
    if (ch === '\\' && pos + 1 < text.length) {
      pos += 2;
      continue;
    }
    if (opener === '(' && ch === '(') return -1;
    if (ch === closer) {
      return skipOptionalNewlineSpaces(text, pos + 1);
    }
    pos += 1;
  }
  return -1;
}

function parseInlineLink(text, openParenPos) {
  let pos = skipOptionalNewlineSpaces(text, openParenPos + 1);
  if (pos >= text.length) return null;

  let dest = '';
  if (text[pos] === '<') {
    pos += 1;
    const start = pos;
    while (pos < text.length && text[pos] !== '>' && text[pos] !== '\n') {
      if (text[pos] === '\\' && pos + 1 < text.length) {
        pos += 2;
        continue;
      }
      pos += 1;
    }
    if (pos >= text.length || text[pos] !== '>') return null;
    dest = unescapeDestination(text.slice(start, pos).trim());
    pos += 1;
  } else {
    const start = pos;
    let depth = 0;
    while (pos < text.length) {
      const ch = text[pos];
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') break;
      if (ch === '\\' && pos + 1 < text.length) {
        pos += 2;
        continue;
      }
      if (ch === '(') depth += 1;
      else if (ch === ')') {
        if (depth === 0) break;
        depth -= 1;
      }
      pos += 1;
    }
    if (depth !== 0 || pos === start) return null;
    dest = unescapeDestination(text.slice(start, pos).trim());
  }

  pos = skipOptionalInlineTitle(text, pos);
  if (pos < 0 || pos >= text.length || text[pos] !== ')') return null;
  return { dest, endPos: pos + 1 };
}

function parseTitleLines(lines, curIdx, tail) {
  if (!tail) return curIdx + 1;
  const opener = tail[0];
  if (opener !== '"' && opener !== "'" && opener !== '(') return -1;
  const closer = opener === '(' ? ')' : opener;

  let pos = 1;
  let line = tail;
  while (curIdx < lines.length) {
    while (pos < line.length) {
      const ch = line[pos];
      if (ch === '\\' && pos + 1 < line.length) {
        pos += 2;
        continue;
      }
      if (opener === '(' && ch === '(') return -1;
      if (ch === closer) {
        return line.slice(pos + 1).trim() === '' ? curIdx + 1 : -1;
      }
      pos += 1;
    }
    curIdx += 1;
    if (curIdx >= lines.length || lines[curIdx].trim() === '') return -1;
    line = lines[curIdx];
    pos = 0;
  }
  return -1;
}

function parseRefDefinition(lines, idx) {
  const match = lines[idx].match(/^[ \t]{0,3}\[([^\]\n]+)\]:[ \t]*(.*)$/);
  if (!match || isEscaped(lines[idx], lines[idx].indexOf('['))) return null;

  const key = normalizeLabel(match[1]);
  let cur = idx;
  let rest = match[2].trim();
  if (!rest) {
    if (cur + 1 >= lines.length || lines[cur + 1].trim() === '') return null;
    cur += 1;
    rest = lines[cur].trim();
  }

  let dest = '';
  let tail = '';
  if (rest.startsWith('<')) {
    let pos = 1;
    while (pos < rest.length && rest[pos] !== '>') {
      if (rest[pos] === '\\' && pos + 1 < rest.length) {
        pos += 2;
        continue;
      }
      pos += 1;
    }
    if (pos >= rest.length) return null;
    dest = unescapeDestination(rest.slice(1, pos).trim());
    tail = rest.slice(pos + 1).trim();
  } else {
    const wsIdx = rest.search(/[ \t]/);
    if (wsIdx === -1) {
      dest = unescapeDestination(rest);
    } else {
      dest = unescapeDestination(rest.slice(0, wsIdx));
      tail = rest.slice(wsIdx).trim();
    }
  }
  if (!key || !dest) return null;

  let nextIdx = cur + 1;
  if (tail) {
    nextIdx = parseTitleLines(lines, cur, tail);
    if (nextIdx === -1) return null;
  } else if (cur + 1 < lines.length && /^[ \t]*["'(]/.test(lines[cur + 1])) {
    const titleEnd = parseTitleLines(lines, cur + 1, lines[cur + 1].trim());
    if (titleEnd !== -1) nextIdx = titleEnd;
  }
  return { key, dest, nextIdx };
}

function findClosingBracket(text, startPos) {
  for (let pos = startPos; pos < text.length; pos += 1) {
    const ch = text[pos];
    if (ch === '\\' && pos + 1 < text.length) {
      pos += 1;
      continue;
    }
    if (ch === '[') return -1;
    if (ch === ']') return pos;
  }
  return -1;
}

function deactivateOuterLinks(openers) {
  for (const entry of openers) {
    if (!entry.isImage) entry.active = false;
  }
}

function extractLinkTargets(cleaned, { includeUnusedDefs = true } = {}) {
  const defs = new Map();
  const bodyLines = [];
  const lines = cleaned.split(/\r?\n/);
  for (let i = 0; i < lines.length; ) {
    const parsedDef = parseRefDefinition(lines, i);
    if (parsedDef) {
      if (!defs.has(parsedDef.key)) defs.set(parsedDef.key, parsedDef.dest);
      i = parsedDef.nextIdx;
    } else {
      bodyLines.push(lines[i]);
      i += 1;
    }
  }

  const targets = [];
  const usedLabels = new Set();
  for (const para of bodyLines.join('\n').split(/\n[ \t]*\n/)) {
    const openers = [];
    for (let i = 0; i < para.length; ) {
      if (para[i] === '\\' && i + 1 < para.length) {
        i += 2;
        continue;
      }
      if (para[i] === '!' && para[i + 1] === '[') {
        openers.push({ isImage: true, contentStart: i + 2, active: true });
        i += 2;
        continue;
      }
      if (para[i] === '[') {
        openers.push({ isImage: false, contentStart: i + 1, active: true });
        i += 1;
        continue;
      }
      if (para[i] === ']') {
        if (openers.length === 0) {
          i += 1;
          continue;
        }
        const opener = openers.pop();
        if (!opener.active) {
          i += 1;
          continue;
        }
        if (para[i + 1] === '(') {
          const parsed = parseInlineLink(para, i + 1);
          if (parsed) {
            if (parsed.dest) targets.push(parsed.dest);
            if (!opener.isImage) deactivateOuterLinks(openers);
            i = parsed.endPos;
            continue;
          }
        }
        let hasBracketedRef = false;
        if (para[i + 1] === '[') {
          const close2 = findClosingBracket(para, i + 2);
          if (close2 !== -1) {
            const secondLabel = para.slice(i + 2, close2);
            if (secondLabel === '' || normalizeLabel(secondLabel) !== '') {
              hasBracketedRef = true;
              const rawLabel = secondLabel || para.slice(opener.contentStart, i);
              const key = normalizeLabel(rawLabel);
              if (defs.has(key)) {
                usedLabels.add(key);
                if (!opener.isImage) deactivateOuterLinks(openers);
                i = close2 + 1;
                continue;
              }
            }
          }
        }
        if (!hasBracketedRef) {
          const key = normalizeLabel(para.slice(opener.contentStart, i));
          if (defs.has(key)) {
            usedLabels.add(key);
            if (!opener.isImage) deactivateOuterLinks(openers);
          }
        }
        i += 1;
        continue;
      }
      i += 1;
    }
  }

  if (includeUnusedDefs) {
    targets.push(...defs.values());
  } else {
    for (const [label, dest] of defs) {
      if (usedLabels.has(label)) targets.push(dest);
    }
  }
  return targets;
}

function normalizeRelativeTarget(dest) {
  if (!dest || /^(#|https?:\/\/|mailto:|file:\/\/)/.test(dest)) return null;
  const targetPath = dest.split('#')[0].split('?')[0];
  return targetPath || null;
}

test('all Markdown relative links resolve', () => {
  const mdFiles = listMarkdownFiles();
  assert.ok(mdFiles.length > 0, 'expected Markdown files');

  const broken = [];
  for (const mdFile of mdFiles) {
    const cleaned = stripCode(fs.readFileSync(mdFile, 'utf8'));
    for (const rawTarget of extractLinkTargets(cleaned)) {
      const targetPath = normalizeRelativeTarget(rawTarget);
      if (!targetPath) continue;
      const resolved = path.resolve(path.dirname(mdFile), targetPath);
      if (!fs.existsSync(resolved)) {
        broken.push(`${path.relative(root, mdFile)} -> ${rawTarget}`);
      }
    }
  }
  assert.deepEqual(broken, [], `broken relative Markdown links:\n${broken.join('\n')}`);
});

test('every documented script path exists', () => {
  const missing = [];
  for (const mdFile of listMarkdownFiles()) {
    const content = fs.readFileSync(mdFile, 'utf8');
    for (const match of content.matchAll(/\bscripts\/([A-Za-z0-9._-]+\.(?:sh|js|py))\b/g)) {
      const relScript = path.join('scripts', match[1]);
      if (!fs.existsSync(path.join(root, relScript))) {
        missing.push(`${path.relative(root, mdFile)} -> ${relScript}`);
      }
    }
  }
  assert.deepEqual(missing, [], `missing documented script paths:\n${missing.join('\n')}`);
});

test('README configuration table variables exist in config.env.example', () => {
  const readme = read('README.md');
  const sectionMatch = readme.match(/## Configuration \(`config\.env`\)\n([\s\S]*?)\n---/);
  assert.ok(sectionMatch, 'missing Configuration (`config.env`) section in README.md');

  const configExample = read('config.env.example');
  const definedVars = new Set(
    Array.from(configExample.matchAll(/^(?:#\s*)?([A-Z][A-Z0-9_]+)=/gm), (m) => m[1]),
  );
  // Commented legacy aliases documented in prose inside config.env.example
  for (const legacy of ['DAILY_LOCAL_BACKUP', 'DAILY_R2_BACKUP', 'DAILY_DO_BACKUP']) {
    if (configExample.includes(legacy)) definedVars.add(legacy);
  }

  const varsList = [...definedVars];
  const missing = [];
  for (const line of sectionMatch[1].split('\n')) {
    if (!line.trimStart().startsWith('|')) continue;
    const cells = line.trim().split('|').map((c) => c.trim());
    if (cells.length < 3) continue;
    const keyVarsCell = cells[2];
    for (const match of keyVarsCell.matchAll(/`([A-Z][A-Z0-9_]*\*?)`/g)) {
      const token = match[1];
      if (token.endsWith('*')) {
        const prefix = token.slice(0, -1);
        if (!varsList.some((v) => v.startsWith(prefix))) {
          missing.push(token);
        }
      } else if (!definedVars.has(token)) {
        missing.push(token);
      }
    }
  }
  assert.deepEqual(missing, [], `README config table references undefined variables: ${missing.join(', ')}`);
});

test('README pinned Wrangler and Node versions match package.json', () => {
  const pkg = JSON.parse(read('package.json'));
  const readme = read('README.md');
  const wranglerVer = pkg.devDependencies.wrangler;
  const nodeVer = pkg.devEngines.runtime.version;

  const wranglerMatch = readme.match(/Wrangler \(`([^`]+)`\)/);
  assert.ok(wranglerMatch, 'README.md must document pinned Wrangler (`<version>`)');
  assert.equal(wranglerMatch[1], wranglerVer, 'README.md Wrangler pin mismatch');

  const patchRefs = [...readme.matchAll(/patches\/wrangler@([^)\s`]+)\.patch/g)];
  assert.ok(patchRefs.length > 0, 'README.md must reference patches/wrangler@<version>.patch');
  for (const m of patchRefs) {
    assert.equal(m[1], wranglerVer, 'README.md patch path Wrangler version mismatch');
  }

  const nodeMatch = readme.match(/Node\.js \(`([^`]+)` via `devEngines\.runtime`\)/);
  assert.ok(nodeMatch, 'README.md must document pinned Node.js (`<version>` via `devEngines.runtime`)');
  assert.equal(nodeMatch[1], nodeVer, 'README.md Node.js version mismatch');
});

test('every docs/*.md file is linked from README.md', () => {
  const readme = read('README.md');
  const docsDir = path.join(root, 'docs');
  const docFiles = fs
    .readdirSync(docsDir)
    .filter((name) => name.endsWith('.md'))
    .sort();
  assert.ok(docFiles.length > 0, 'expected files in docs/');

  const linkDestinations = new Set();
  for (const rawTarget of extractLinkTargets(stripCode(readme), { includeUnusedDefs: false })) {
    const targetPath = normalizeRelativeTarget(rawTarget);
    if (!targetPath) continue;
    const rel = path.relative(root, path.resolve(root, targetPath)).split(path.sep).join('/');
    linkDestinations.add(rel);
  }

  const unlinked = docFiles.filter((name) => !linkDestinations.has(`docs/${name}`));
  assert.deepEqual(unlinked, [], `docs/*.md files not linked from README.md: ${unlinked.join(', ')}`);
});
