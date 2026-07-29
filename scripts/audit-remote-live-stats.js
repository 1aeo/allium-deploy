#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function assertSamePaths(label, expected, actual) {
  const expectedSorted = sorted(expected);
  const actualSorted = sorted(actual);
  if (expectedSorted.join('\n') !== actualSorted.join('\n')) {
    const expectedSet = new Set(expectedSorted);
    const actualSet = new Set(actualSorted);
    const missing = expectedSorted.filter((value) => !actualSet.has(value));
    const extra = actualSorted.filter((value) => !expectedSet.has(value));
    throw new Error(`${label} differ; missing=${JSON.stringify(missing)} extra=${JSON.stringify(extra)}`);
  }
}

async function defaultRunRclone(rclone, args, timeoutMs) {
  const { stdout } = await execFileAsync(rclone, args, {
    timeout: timeoutMs,
    maxBuffer: 16 * 1024 * 1024,
  });
  return stdout;
}

async function mapLimit(values, limit, callback) {
  let cursor = 0;
  const results = new Array(values.length);
  const workers = Array.from({ length: Math.min(limit, values.length) }, async () => {
    while (cursor < values.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await callback(values[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

function parseJson(payload, label) {
  try {
    return JSON.parse(payload);
  } catch (error) {
    throw new Error(`${label} returned invalid JSON: ${error.message}`);
  }
}

function parseSize(payload, label) {
  const parsed = parseJson(payload, label);
  if (!Number.isSafeInteger(parsed.count) || parsed.count < 0
      || !Number.isSafeInteger(parsed.bytes) || parsed.bytes < 0) {
    throw new Error(`${label} returned invalid count or bytes`);
  }
  return { count: parsed.count, bytes: parsed.bytes };
}

export async function measureRemoteLiveStats({
  source,
  remote,
  rclone = 'rclone',
  concurrency = 16,
  timeoutMs = 120000,
  runRclone = defaultRunRclone,
}) {
  if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 64) {
    throw new Error('concurrency must be an integer from 1 through 64');
  }
  const sourceEntries = await fs.readdir(source, { withFileTypes: true });
  const sourceDirectories = [];
  const sourceRootFiles = new Map();
  for (const entry of sourceEntries) {
    if (entry.name === '_headers') continue;
    if (entry.name.includes('\n') || entry.name.includes('/')) {
      throw new Error(`unsupported source root path: ${JSON.stringify(entry.name)}`);
    }
    if (entry.isDirectory()) {
      sourceDirectories.push(entry.name);
    } else if (entry.isFile()) {
      const stat = await fs.stat(path.join(source, entry.name));
      sourceRootFiles.set(entry.name, stat.size);
    } else {
      throw new Error(`unsupported source root entry type: ${entry.name}`);
    }
  }

  const rootPayload = await runRclone(rclone, [
    'lsjson', remote, '--max-depth', '1', '--no-mimetype', '--no-modtime', '--log-level', 'ERROR',
  ], timeoutMs);
  const rootEntries = parseJson(rootPayload, `${remote} root listing`);
  if (!Array.isArray(rootEntries)) throw new Error(`${remote} root listing is not an array`);

  const remoteDirectories = [];
  const remoteRootFiles = new Map();
  for (const entry of rootEntries) {
    if (!entry || typeof entry.Path !== 'string' || typeof entry.IsDir !== 'boolean') {
      throw new Error(`${remote} root listing contains an invalid entry`);
    }
    if (entry.Path === '_backups' || entry.Path === '_headers') continue;
    if (entry.IsDir) {
      remoteDirectories.push(entry.Path.replace(/\/$/, ''));
    } else {
      if (!Number.isSafeInteger(entry.Size) || entry.Size < 0) {
        throw new Error(`${remote} root file has invalid size: ${entry.Path}`);
      }
      remoteRootFiles.set(entry.Path, entry.Size);
    }
  }

  assertSamePaths(`${remote} live root directories`, sourceDirectories, remoteDirectories);
  assertSamePaths(`${remote} live root files`, sourceRootFiles.keys(), remoteRootFiles.keys());
  for (const [name, size] of sourceRootFiles) {
    if (remoteRootFiles.get(name) !== size) {
      throw new Error(`${remote} root file size differs: ${name}`);
    }
  }

  const remoteBase = remote.replace(/\/$/, '');
  const directoryStats = await mapLimit(sorted(sourceDirectories), concurrency, async (directory) => {
    const payload = await runRclone(rclone, [
      'size', `${remoteBase}/${directory}`, '--json', '--log-level', 'ERROR',
    ], timeoutMs);
    return parseSize(payload, `${remote}/${directory}`);
  });

  const rootBytes = [...remoteRootFiles.values()].reduce((total, value) => total + value, 0);
  return directoryStats.reduce((total, value) => ({
    count: total.count + value.count,
    bytes: total.bytes + value.bytes,
  }), { count: remoteRootFiles.size, bytes: rootBytes });
}

function argument(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  if (!args[index + 1]) throw new Error(`${name} requires a value`);
  return args[index + 1];
}

async function runCli() {
  const args = process.argv.slice(2);
  const source = argument(args, '--source');
  const remote = argument(args, '--remote');
  const rclone = argument(args, '--rclone', 'rclone');
  if (!source || !remote) throw new Error('--source and --remote are required');
  const report = await measureRemoteLiveStats({
    source: path.resolve(source),
    remote,
    rclone,
    concurrency: Number(argument(args, '--concurrency', '16')),
    timeoutMs: Number(argument(args, '--timeout-seconds', '120')) * 1000,
  });
  process.stdout.write(`${JSON.stringify(report)}\n`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  try {
    await runCli();
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ok: false, errors: [error.message] })}\n`);
    process.exitCode = 1;
  }
}
