#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const JOB_HEADERS = [
  'started_utc',
  'finished_utc',
  'exit_status',
  'total_duration_seconds',
  'cadence_ok',
  'shadow_counter',
];
const SHADOW_HEADERS = [
  'timestamp_utc',
  'version_id',
  'duration_seconds',
  'file_count',
  'byte_count',
  'preview_url',
  'consecutive_successes',
];
const PROMOTION_HEADERS = ['timestamp_utc', 'version_id', 'exit_status'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function parseTsv(text, headers, label, errors) {
  const lines = text.trimEnd().split('\n');
  if (!text.trim() || lines.length < 1) {
    errors.push(`${label}: file is empty`);
    return [];
  }
  if (lines[0].replace(/\r$/, '').split('\t').join('\t') !== headers.join('\t')) {
    errors.push(`${label}: unexpected header`);
    return [];
  }
  return lines.slice(1).map((line, index) => {
    const fields = line.replace(/\r$/, '').split('\t');
    if (fields.length !== headers.length) {
      errors.push(`${label}: row ${index + 2} has ${fields.length} fields; expected ${headers.length}`);
    }
    return Object.fromEntries(headers.map((header, column) => [header, fields[column] ?? '']));
  });
}

function timestamp(value, label, errors) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    errors.push(`${label}: expected a second-resolution UTC timestamp`);
    return Number.NaN;
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) errors.push(`${label}: invalid timestamp`);
  return parsed;
}

function integer(value, label, errors) {
  if (!/^[0-9]+$/.test(String(value))) {
    errors.push(`${label}: expected a nonnegative integer`);
    return Number.NaN;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) errors.push(`${label}: integer is outside the accepted range`);
  return parsed;
}

export function auditStage4({
  jobsTsv,
  shadowTsv,
  promotionsTsv,
  startedUtc,
  nowUtc = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  minimumJobs = 48,
  minimumElapsedSeconds = 86400,
  maxJobSeconds = 1800,
}) {
  const errors = [];
  const started = timestamp(startedUtc, 'startedUtc', errors);
  const now = timestamp(nowUtc, 'nowUtc', errors);
  const requiredJobs = integer(minimumJobs, 'minimumJobs', errors);
  const requiredElapsed = integer(minimumElapsedSeconds, 'minimumElapsedSeconds', errors);
  const jobLimit = integer(maxJobSeconds, 'maxJobSeconds', errors);
  const allJobs = parseTsv(jobsTsv, JOB_HEADERS, 'job summary', errors);
  const allShadow = parseTsv(shadowTsv, SHADOW_HEADERS, 'shadow summary', errors);
  const allPromotions = parseTsv(promotionsTsv, PROMOTION_HEADERS, 'promotion summary', errors);

  const rowsSince = (rows, field, label) => rows.filter((row, index) => {
    const parsed = timestamp(row[field], `${label}: row ${index + 2} ${field}`, errors);
    return Number.isFinite(parsed) && parsed >= started;
  });
  const jobs = rowsSince(allJobs, 'started_utc', 'job summary');
  const shadow = rowsSince(allShadow, 'timestamp_utc', 'shadow summary');
  const promotions = rowsSince(allPromotions, 'timestamp_utc', 'promotion summary');
  const rowCount = Math.max(jobs.length, shadow.length, promotions.length);
  const versionIds = new Set();
  let previousStart = null;
  let previousCounter = null;
  let maxJobDurationSeconds = 0;

  if (jobs.length !== shadow.length || jobs.length !== promotions.length) {
    errors.push(`Stage 4 row counts differ: jobs=${jobs.length}, shadow=${shadow.length}, promotions=${promotions.length}`);
  }

  for (let index = 0; index < rowCount; index += 1) {
    const job = jobs[index];
    const candidate = shadow[index];
    const promotion = promotions[index];
    const label = `Stage 4 execution ${index + 1}`;
    if (!job || !candidate || !promotion) continue;

    const jobStart = timestamp(job.started_utc, `${label} job start`, errors);
    const jobFinish = timestamp(job.finished_utc, `${label} job finish`, errors);
    const candidateTime = timestamp(candidate.timestamp_utc, `${label} candidate timestamp`, errors);
    const promotionTime = timestamp(promotion.timestamp_utc, `${label} promotion timestamp`, errors);
    const jobStatus = integer(job.exit_status, `${label} job status`, errors);
    const promotionStatus = integer(promotion.exit_status, `${label} promotion status`, errors);
    const jobDuration = integer(job.total_duration_seconds, `${label} job duration`, errors);
    const jobCounter = integer(job.shadow_counter, `${label} job counter`, errors);
    const candidateCounter = integer(candidate.consecutive_successes, `${label} candidate counter`, errors);

    if (jobStatus !== 0) errors.push(`${label}: job exit status is ${jobStatus}`);
    if (promotionStatus !== 0) errors.push(`${label}: promotion exit status is ${promotionStatus}`);
    if (job.cadence_ok !== 'true') errors.push(`${label}: cadence_ok is not true`);
    if (jobDuration > jobLimit) errors.push(`${label}: duration ${jobDuration}s exceeds ${jobLimit}s`);
    maxJobDurationSeconds = Math.max(maxJobDurationSeconds, jobDuration);

    if (Number.isFinite(jobStart) && Number.isFinite(jobFinish)) {
      if ((jobFinish - jobStart) / 1000 !== jobDuration) {
        errors.push(`${label}: timestamps do not match recorded duration`);
      }
      const date = new Date(jobStart);
      if (![15, 45].includes(date.getUTCMinutes()) || date.getUTCSeconds() > 10) {
        errors.push(`${label}: job did not start in a :15/:45 scheduler slot`);
      }
      if (previousStart !== null) {
        const spacing = (jobStart - previousStart) / 1000;
        if (spacing < 1780 || spacing > 1820) {
          errors.push(`${label}: scheduled-start spacing is ${spacing}s, expected approximately 1800s`);
        }
      }
      previousStart = jobStart;
    }

    if (Number.isFinite(jobStart) && Number.isFinite(jobFinish) && Number.isFinite(candidateTime)
        && (candidateTime < jobStart || candidateTime > jobFinish)) {
      errors.push(`${label}: candidate verification is outside its scheduled job`);
    }
    if (Number.isFinite(candidateTime) && Number.isFinite(jobFinish) && Number.isFinite(promotionTime)
        && (promotionTime < candidateTime || promotionTime > jobFinish)) {
      errors.push(`${label}: promotion is outside the verified-candidate job window`);
    }
    if (!UUID.test(candidate.version_id) || !UUID.test(promotion.version_id)) {
      errors.push(`${label}: invalid Worker version ID`);
    }
    if (candidate.version_id !== promotion.version_id) {
      errors.push(`${label}: promoted version does not match the verified candidate`);
    }
    if (versionIds.has(promotion.version_id)) errors.push(`${label}: duplicate promoted version ID`);
    versionIds.add(promotion.version_id);
    if (jobCounter !== candidateCounter) errors.push(`${label}: job and candidate counters differ`);
    if (previousCounter !== null && jobCounter !== previousCounter + 1) {
      errors.push(`${label}: counter advanced from ${previousCounter} to ${jobCounter}`);
    }
    previousCounter = jobCounter;
  }

  const firstPromotion = promotions[0] ? Date.parse(promotions[0].timestamp_utc) : Number.NaN;
  const elapsedSeconds = Number.isFinite(firstPromotion) && Number.isFinite(now)
    ? Math.floor((now - firstPromotion) / 1000)
    : 0;
  if (Number.isFinite(now) && Number.isFinite(firstPromotion) && now < firstPromotion) {
    errors.push('nowUtc precedes the first Stage 4 promotion');
  }

  const complete = jobs.length >= requiredJobs && elapsedSeconds >= requiredElapsed;
  return {
    ok: errors.length === 0,
    progress: {
      jobs: jobs.length,
      verifiedCandidates: shadow.length,
      successfulPromotions: promotions.filter((row) => row.exit_status === '0').length,
      minimumJobs: requiredJobs,
      elapsedSeconds,
      minimumElapsedSeconds: requiredElapsed,
      complete,
    },
    window: {
      firstJobStartedUtc: jobs[0]?.started_utc ?? null,
      firstPromotionUtc: promotions[0]?.timestamp_utc ?? null,
      lastJobFinishedUtc: jobs.at(-1)?.finished_utc ?? null,
      lastPromotionUtc: promotions.at(-1)?.timestamp_utc ?? null,
      maxJobDurationSeconds,
    },
    errors,
  };
}

function argument(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  if (!args[index + 1]) throw new Error(`${name} requires a value`);
  return args[index + 1];
}

function runCli() {
  const args = process.argv.slice(2);
  const report = auditStage4({
    jobsTsv: fs.readFileSync(path.resolve(argument(args, '--jobs', 'logs/cfassets-stage2-job-summary.tsv')), 'utf8'),
    shadowTsv: fs.readFileSync(path.resolve(argument(args, '--shadow', 'logs/cfassets-shadow-summary.tsv')), 'utf8'),
    promotionsTsv: fs.readFileSync(path.resolve(argument(args, '--promotions', 'logs/cfassets-promotion-summary.tsv')), 'utf8'),
    startedUtc: argument(args, '--started', '2026-07-28T02:45:01Z'),
    nowUtc: argument(args, '--now', new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')),
    minimumJobs: Number(argument(args, '--minimum-jobs', '48')),
    minimumElapsedSeconds: Number(argument(args, '--minimum-elapsed-seconds', '86400')),
    maxJobSeconds: Number(argument(args, '--max-job-seconds', '1800')),
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.ok || (args.includes('--require-complete') && !report.progress.complete)) process.exitCode = 1;
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
