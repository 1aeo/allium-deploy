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

test('all Markdown relative links resolve', () => {
  const mdFiles = listMarkdownFiles();
  assert.ok(mdFiles.length > 0, 'expected Markdown files');

  const broken = [];
  for (const mdFile of mdFiles) {
    const cleaned = stripCode(fs.readFileSync(mdFile, 'utf8'));
    for (const match of cleaned.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
      const target = match[1].trim().split(/\s+/)[0].replace(/^<|>$/g, '');
      if (!target || /^(#|https?:\/\/|mailto:|file:\/\/)/.test(target)) continue;
      const targetPath = target.split('#')[0].split('?')[0];
      if (!targetPath) continue;
      const resolved = path.resolve(path.dirname(mdFile), targetPath);
      if (!fs.existsSync(resolved)) {
        broken.push(`${path.relative(root, mdFile)} -> ${match[1]}`);
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

  assert.ok(readme.includes(wranglerVer), `README.md must reference Wrangler ${wranglerVer}`);
  assert.ok(
    readme.includes(`patches/wrangler@${wranglerVer}.patch`),
    `README.md must reference patches/wrangler@${wranglerVer}.patch`,
  );
  assert.ok(readme.includes(nodeVer), `README.md must reference Node.js ${nodeVer}`);
});

test('every docs/*.md file is linked from README.md', () => {
  const readme = read('README.md');
  const docsDir = path.join(root, 'docs');
  const docFiles = fs
    .readdirSync(docsDir)
    .filter((name) => name.endsWith('.md'))
    .sort();
  assert.ok(docFiles.length > 0, 'expected files in docs/');

  const unlinked = docFiles.filter((name) => !readme.includes(`docs/${name}`));
  assert.deepEqual(unlinked, [], `docs/*.md files not linked from README.md: ${unlinked.join(', ')}`);
});
