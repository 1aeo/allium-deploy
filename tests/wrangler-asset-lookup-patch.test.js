// The pnpm patch for Wrangler's asset upload replaces a per-file scan of the
// asset manifest with a hash index. These tests check that the patch matches the
// pinned Wrangler and the lockfile, and that the patched lookup returns exactly
// what the original did, using the lines from the patch file itself.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (file) => fs.readFileSync(new URL(file, root), 'utf8');
const pin = JSON.parse(read('package.json')).devDependencies.wrangler;
const patchFile = `patches/wrangler@${pin}.patch`;
const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function patchLines(prefix) {
  return read(patchFile)
    .split('\n')
    .filter((line) => line.startsWith(prefix) && !line.startsWith(prefix.repeat(3)))
    .map((line) => line.slice(1));
}

// Split each side into the manifest setup and the per-hash lookup, and return a
// factory: manifest -> (fileHash -> manifest entry).
function lookupFrom(lines) {
  const index = lines.findIndex((line) => line.includes('const manifestEntry'));
  assert.ok(index > 0, 'patch side has no manifestEntry lookup');
  const setup = lines.slice(0, index).join('\n');
  const lookup = lines.slice(index).join('\n');
  return new Function('manifest', `${setup}\nreturn (fileHash) => {\n${lookup}\nreturn manifestEntry;\n};`);
}

const original = (manifest) => lookupFrom(patchLines('-'))(manifest);
const patched = (manifest) => lookupFrom(patchLines('+'))(manifest);

function manifestWithDuplicates(count, seed) {
  const manifest = {};
  let state = seed;
  const next = () => (state = (state * 1103515245 + 12345) % 2147483648);
  for (let i = 0; i < count; i++) {
    // About one file in five shares its content (hash) with an earlier file.
    const content = next() % 5 === 0 ? next() % Math.max(1, i) : i;
    manifest[`/dir${i % 17}/file-${i}.png`] = {
      hash: crypto.createHash('sha256').update(String(content)).digest('hex').slice(0, 32),
      size: next() % 50000,
    };
  }
  return manifest;
}

test('the patch is for the pinned Wrangler version', () => {
  assert.match(pin, /^\d+\.\d+\.\d+$/);
  assert.ok(fs.existsSync(new URL(patchFile, root)), `${patchFile} is missing`);
  assert.match(
    read('pnpm-workspace.yaml'),
    new RegExp(`\\npatchedDependencies:\\n  wrangler@${escape(pin)}: ${escape(patchFile)}\\n`),
    'pnpm-workspace.yaml does not patch the pinned Wrangler',
  );
});

test('the lockfile pins this exact patch file', () => {
  const hash = crypto.createHash('sha256').update(read(patchFile)).digest('hex');
  const lock = read('pnpm-lock.yaml');
  assert.ok(
    lock.includes(`patchedDependencies:\n  wrangler@${pin}:\n    hash: ${hash}\n    path: ${patchFile}\n`),
    'pnpm-lock.yaml does not record the current patch hash; run pnpm install',
  );
  assert.ok(lock.includes(`wrangler@${pin}(patch_hash=${hash})`), 'the lockfile does not install the patched Wrangler');
});

test('the patch changes only the asset manifest lookup', () => {
  const patch = read(patchFile);
  assert.equal((patch.match(/^diff --git /gm) || []).length, 1);
  assert.match(patch, /^diff --git a\/wrangler-dist\/cli\.js b\/wrangler-dist\/cli\.js$/m);
  assert.equal((patch.match(/^@@ /gm) || []).length, 1);
  assert.deepEqual(
    patchLines('-').map((line) => line.trim()),
    [
      'const manifestLookup = Object.entries(manifest);',
      'const manifestEntry = manifestLookup.find(',
      '(file3) => file3[1].hash === fileHash',
      ');',
    ],
  );
});

test('the patched lookup returns the same entry as the original for every hash', () => {
  for (const seed of [1, 7, 42]) {
    const manifest = manifestWithDuplicates(5000, seed);
    const before = original(manifest);
    const after = patched(manifest);
    const hashes = new Set(Object.values(manifest).map((entry) => entry.hash));
    assert.ok(hashes.size < Object.keys(manifest).length, 'fixture has no duplicate content');
    for (const hash of hashes) {
      assert.deepEqual(after(hash), before(hash), `different entry for ${hash}`);
    }
    assert.equal(after('0'.repeat(32)), undefined);
    assert.equal(before('0'.repeat(32)), undefined);
  }
});

test('the patched lookup stays fast on a large manifest', () => {
  const manifest = manifestWithDuplicates(100000, 3);
  const hashes = Object.values(manifest).map((entry) => entry.hash);
  const started = process.hrtime.bigint();
  const lookup = patched(manifest);
  for (let i = 0; i < 50000; i++) {
    assert.ok(lookup(hashes[(i * 7919) % hashes.length]));
  }
  const seconds = Number(process.hrtime.bigint() - started) / 1e9;
  assert.ok(seconds < 5, `50,000 lookups in a 100,000-file manifest took ${seconds.toFixed(1)} s`);
});
