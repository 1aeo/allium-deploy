#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SHADOW_HEADERS = [
  'timestamp_utc',
  'version_id',
  'duration_seconds',
  'file_count',
  'byte_count',
  'preview_url',
  'consecutive_successes',
];

const JOB_HEADERS = [
  'started_utc',
  'finished_utc',
  'exit_status',
  'total_duration_seconds',
  'cadence_ok',
  'shadow_counter',
];

function parseTsv(text, expectedHeaders, label, errors) {
  const lines = text.trimEnd().split('\n');
  if (!text.trim() || lines.length === 0) {
    errors.push(`${label}: file is empty`);
    return [];
  }

  const headers = lines[0].replace(/\r$/, '').split('\t');
  if (headers.join('\t') !== expectedHeaders.join('\t')) {
    errors.push(`${label}: unexpected header`);
    return [];
  }

  return lines.slice(1).map((line, index) => {
    const values = line.replace(/\r$/, '').split('\t');
    if (values.length !== expectedHeaders.length) {
      errors.push(`${label}: row ${index + 2} has ${values.length} fields; expected ${expectedHeaders.length}`);
    }
    return Object.fromEntries(expectedHeaders.map((header, column) => [header, values[column] ?? '']));
  });
}

function integer(value, label, errors, { positive = false } = {}) {
  if (!/^[0-9]+$/.test(String(value))) {
    errors.push(`${label}: expected an integer, got ${JSON.stringify(value)}`);
    return Number.NaN;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || (positive && parsed < 1)) {
    errors.push(`${label}: integer is outside the accepted range`);
    return Number.NaN;
  }
  return parsed;
}

function utcTimestamp(value, label, errors) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    errors.push(`${label}: expected a second-resolution UTC timestamp`);
    return Number.NaN;
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) errors.push(`${label}: invalid timestamp`);
  return parsed;
}

function trailingSegment(rows, counter, counterField, label, errors) {
  if (counter === 0) return [];
  if (rows.length < counter) {
    errors.push(`${label}: only ${rows.length} rows exist for counter ${counter}`);
    return rows;
  }

  const segment = rows.slice(-counter);
  segment.forEach((row, index) => {
    const actual = integer(row[counterField], `${label}: row ${rows.length - counter + index + 2} ${counterField}`, errors);
    const expected = index + 1;
    if (actual !== expected) {
      errors.push(`${label}: current segment expected ${counterField}=${expected}, got ${row[counterField]}`);
    }
  });
  return segment;
}

function percentDelta(previous, current) {
  return previous === 0 ? Number.POSITIVE_INFINITY : Math.abs(current - previous) / previous * 100;
}

export function auditSoak({
  shadowTsv,
  jobTsv,
  counter,
  target = 10,
  maxDeltaPercent = 10,
  maxJobSeconds = 1800,
  maxAssetFiles = 100000,
}) {
  const errors = [];
  const current = integer(counter, 'counter', errors);
  const targetCount = integer(target, 'target', errors, { positive: true });
  const shadowRows = parseTsv(shadowTsv, SHADOW_HEADERS, 'shadow summary', errors);
  const jobRows = parseTsv(jobTsv, JOB_HEADERS, 'job summary', errors);

  if (!Number.isFinite(maxDeltaPercent) || maxDeltaPercent < 0) {
    errors.push('maxDeltaPercent: expected a nonnegative number');
  }
  if (!Number.isSafeInteger(maxJobSeconds) || maxJobSeconds < 1) {
    errors.push('maxJobSeconds: expected a positive integer');
  }
  if (!Number.isSafeInteger(maxAssetFiles) || maxAssetFiles < 1) {
    errors.push('maxAssetFiles: expected a positive integer');
  }

  const shadow = trailingSegment(shadowRows, current, 'consecutive_successes', 'shadow summary', errors);
  const jobs = trailingSegment(jobRows, current, 'shadow_counter', 'job summary', errors);
  const seenVersions = new Set();
  const durations = [];
  const fileCounts = [];
  const byteCounts = [];
  const jobDurations = [];
  const previewUrls = new Set();
  let latestPreviewUrl = null;
  let maxFileDeltaPercent = 0;
  let maxByteDeltaPercent = 0;

  shadow.forEach((row, index) => {
    const rowNumber = shadowRows.length - shadow.length + index + 2;
    const prefix = `shadow summary: row ${rowNumber}`;
    row.timestamp = utcTimestamp(row.timestamp_utc, `${prefix} timestamp_utc`, errors);
    row.duration = integer(row.duration_seconds, `${prefix} duration_seconds`, errors, { positive: true });
    row.files = integer(row.file_count, `${prefix} file_count`, errors, { positive: true });
    row.bytes = integer(row.byte_count, `${prefix} byte_count`, errors, { positive: true });

    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(row.version_id)) {
      errors.push(`${prefix}: invalid Worker version ID`);
    }
    if (seenVersions.has(row.version_id)) errors.push(`${prefix}: duplicate Worker version ID`);
    seenVersions.add(row.version_id);

    try {
      const parsedUrl = new URL(row.preview_url);
      if (parsedUrl.protocol !== 'https:' || !parsedUrl.hostname.endsWith('.workers.dev') || parsedUrl.pathname !== '/') {
        errors.push(`${prefix}: preview URL is not an HTTPS workers.dev root`);
      }
      const expectedVersionPrefix = `${row.version_id.slice(0, 8).toLowerCase()}-`;
      if (!parsedUrl.hostname.toLowerCase().startsWith(expectedVersionPrefix)) {
        errors.push(`${prefix}: preview URL does not match the immutable Worker version prefix`);
      }
    } catch {
      errors.push(`${prefix}: invalid preview URL`);
    }
    if (previewUrls.has(row.preview_url)) errors.push(`${prefix}: versioned preview URL was reused`);
    previewUrls.add(row.preview_url);
    latestPreviewUrl = row.preview_url;

    if (row.files >= maxAssetFiles) {
      errors.push(`${prefix}: ${row.files} files reaches or exceeds the ${maxAssetFiles}-file limit`);
    }
    durations.push(row.duration);
    fileCounts.push(row.files);
    byteCounts.push(row.bytes);

    if (index > 0) {
      const fileDelta = percentDelta(fileCounts[index - 1], row.files);
      const byteDelta = percentDelta(byteCounts[index - 1], row.bytes);
      maxFileDeltaPercent = Math.max(maxFileDeltaPercent, fileDelta);
      maxByteDeltaPercent = Math.max(maxByteDeltaPercent, byteDelta);
      if (fileDelta > maxDeltaPercent) {
        errors.push(`${prefix}: file-count delta ${fileDelta.toFixed(3)}% exceeds ${maxDeltaPercent}%`);
      }
      if (byteDelta > maxDeltaPercent) {
        errors.push(`${prefix}: byte-count delta ${byteDelta.toFixed(3)}% exceeds ${maxDeltaPercent}%`);
      }
    }
  });

  jobs.forEach((row, index) => {
    const rowNumber = jobRows.length - jobs.length + index + 2;
    const prefix = `job summary: row ${rowNumber}`;
    row.started = utcTimestamp(row.started_utc, `${prefix} started_utc`, errors);
    row.finished = utcTimestamp(row.finished_utc, `${prefix} finished_utc`, errors);
    row.status = integer(row.exit_status, `${prefix} exit_status`, errors);
    row.duration = integer(row.total_duration_seconds, `${prefix} total_duration_seconds`, errors, { positive: true });
    if (row.status !== 0) errors.push(`${prefix}: exit status is ${row.status}`);
    if (row.cadence_ok !== 'true') errors.push(`${prefix}: cadence_ok is not true`);
    if (row.duration > maxJobSeconds) errors.push(`${prefix}: duration ${row.duration}s exceeds ${maxJobSeconds}s`);
    if (Number.isFinite(row.started) && Number.isFinite(row.finished)) {
      const measured = (row.finished - row.started) / 1000;
      if (measured !== row.duration) errors.push(`${prefix}: timestamps span ${measured}s but row records ${row.duration}s`);
      const started = new Date(row.started);
      if (![15, 45].includes(started.getUTCMinutes()) || started.getUTCSeconds() > 10) {
        errors.push(`${prefix}: start is not a scheduled :15/:45 slot`);
      }
    }
    if (index > 0 && Number.isFinite(row.started) && Number.isFinite(jobs[index - 1].started)) {
      const spacing = (row.started - jobs[index - 1].started) / 1000;
      if (spacing < 1780 || spacing > 1820) {
        errors.push(`${prefix}: scheduled-start spacing is ${spacing}s, expected approximately 1800s`);
      }
    }
    jobDurations.push(row.duration);
  });

  for (let index = 0; index < Math.min(shadow.length, jobs.length); index += 1) {
    const candidate = shadow[index];
    const job = jobs[index];
    if (Number.isFinite(candidate.timestamp) && Number.isFinite(job.started) && Number.isFinite(job.finished)
        && (candidate.timestamp < job.started || candidate.timestamp > job.finished)) {
      errors.push(`counter ${index + 1}: candidate verification timestamp is outside its scheduled job`);
    }
    if (Number.isFinite(candidate.duration) && Number.isFinite(job.duration) && candidate.duration > job.duration) {
      errors.push(`counter ${index + 1}: Worker duration exceeds whole-job duration`);
    }
  }

  const range = (values) => values.length ? { min: Math.min(...values), max: Math.max(...values) } : null;
  const complete = Number.isFinite(current) && Number.isFinite(targetCount) && current >= targetCount;
  return {
    ok: errors.length === 0,
    progress: { current, target: targetCount, complete },
    currentSegment: {
      shadowRows: shadow.length,
      jobRows: jobs.length,
      firstStartedUtc: jobs[0]?.started_utc ?? null,
      lastFinishedUtc: jobs.at(-1)?.finished_utc ?? null,
      latestPreviewUrl,
      uniqueVersionedPreviewUrls: previewUrls.size,
      workerDurationSeconds: range(durations),
      totalJobDurationSeconds: range(jobDurations),
      assetFiles: range(fileCounts),
      preparedBytes: range(byteCounts),
      maxFileDeltaPercent,
      maxByteDeltaPercent,
    },
    errors,
  };
}

function argumentValue(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  if (!args[index + 1]) throw new Error(`${name} requires a value`);
  return args[index + 1];
}

function runCli() {
  const args = process.argv.slice(2);
  const shadowPath = argumentValue(args, '--shadow', 'logs/cfassets-shadow-summary.tsv');
  const jobPath = argumentValue(args, '--jobs', 'logs/cfassets-stage2-job-summary.tsv');
  const counterPath = argumentValue(args, '--counter', 'logs/cfassets-shadow-consecutive-successes');
  const target = Number(argumentValue(args, '--target', '10'));
  const maxDeltaPercent = Number(argumentValue(args, '--max-delta-percent', '10'));
  const requireComplete = args.includes('--require-complete');
  const report = auditSoak({
    shadowTsv: fs.readFileSync(path.resolve(shadowPath), 'utf8'),
    jobTsv: fs.readFileSync(path.resolve(jobPath), 'utf8'),
    counter: fs.readFileSync(path.resolve(counterPath), 'utf8').trim(),
    target,
    maxDeltaPercent,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.ok || (requireComplete && !report.progress.complete)) process.exitCode = 1;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  try {
    runCli();
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ok: false, errors: [error.message] }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
