/**
 * OASB Benchmark Runner v2
 *
 * Runs real HMA pipeline adapters against the full v2 corpus.
 * Outputs: per-category metrics, flag rates, timing, and comparison data.
 *
 * Usage:
 *   npx tsx scripts/run-benchmark-v2.ts [--limit N] [--adapter ADAPTER]
 *
 * Adapters: tme-only, pipeline, static, all (default)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { HMATMEOnlyAdapter, HMAPipelineAdapter, HMAPipelineStaticAdapter } from '../src/benchmark/hma-pipeline-adapter.js';
import { runBenchmark, formatComparisonTable, type ScannerAdapter } from '../src/benchmark/runner.js';
import type { BenchmarkDataset, BenchmarkSample, AttackCategory, ScannerResult, ATTACK_CATEGORIES } from '../src/benchmark/types.js';

const CATEGORIES: AttackCategory[] = [
  'supply_chain', 'prompt_injection', 'credential_exfiltration',
  'heartbeat_rce', 'unicode_stego', 'privilege_escalation',
  'persistence', 'social_engineering', 'data_exfiltration',
];

interface DetailedResult {
  adapterId: string;
  adapterName: string;
  totalSamples: number;
  totalMalicious: number;
  totalBenign: number;
  flagged: number;
  flagRate: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  avgScanTimeMs: number;
  perCategory: Record<string, {
    total: number;
    detected: number;
    flagRate: number;
    tp: number;
    fp: number;
    fn: number;
    precision: number;
    recall: number;
    f1: number;
  }>;
}

async function runAdapter(
  adapter: ScannerAdapter,
  samples: BenchmarkSample[],
): Promise<{ results: ScannerResult[]; detailed: DetailedResult }> {
  const results: ScannerResult[] = [];
  let totalTimeMs = 0;
  let processed = 0;

  // Process in batches for progress reporting
  const batchSize = 100;
  for (let i = 0; i < samples.length; i += batchSize) {
    const batch = samples.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(s => adapter.scan(s.content, s.id)),
    );
    results.push(...batchResults);
    totalTimeMs += batchResults.reduce((sum, r) => sum + (r.scanTimeMs ?? 0), 0);
    processed += batch.length;

    if (processed % 500 === 0 || processed === samples.length) {
      process.stderr.write(`  [${adapter.id}] ${processed}/${samples.length} samples\n`);
    }
  }

  // Compute detailed metrics
  const detailed = computeDetailedMetrics(adapter, samples, results, totalTimeMs);
  return { results, detailed };
}

function computeDetailedMetrics(
  adapter: ScannerAdapter,
  samples: BenchmarkSample[],
  results: ScannerResult[],
  totalTimeMs: number,
): DetailedResult {
  const resultMap = new Map<string, ScannerResult>();
  for (const r of results) resultMap.set(r.sampleId, r);

  let tp = 0, fp = 0, tn = 0, fn = 0;
  let flagged = 0;

  // Per-category tracking
  const catStats: Record<string, { total: number; detected: number; tp: number; fp: number; fn: number }> = {};
  for (const cat of CATEGORIES) {
    catStats[cat] = { total: 0, detected: 0, tp: 0, fp: 0, fn: 0 };
  }

  for (const sample of samples) {
    const result = resultMap.get(sample.id);
    const scannerSaysMalicious = result?.verdict === 'malicious';

    if (scannerSaysMalicious) flagged++;

    if (sample.label === 'malicious') {
      if (sample.category) {
        catStats[sample.category].total++;
      }
      if (scannerSaysMalicious) {
        tp++;
        if (sample.category) catStats[sample.category].detected++;
        // Check if category matches
        if (sample.category && result?.category === sample.category) {
          catStats[sample.category].tp++;
        } else if (sample.category) {
          // Detected as malicious but wrong category
          catStats[sample.category].fn++;
          if (result?.category && catStats[result.category]) {
            catStats[result.category].fp++;
          }
        }
      } else {
        fn++;
        if (sample.category) catStats[sample.category].fn++;
      }
    } else if (sample.label === 'benign') {
      if (scannerSaysMalicious) {
        fp++;
        if (result?.category && catStats[result.category]) {
          catStats[result.category].fp++;
        }
      } else {
        tn++;
      }
    }
    // edge_case samples are excluded from scoring
  }

  const totalMalicious = samples.filter(s => s.label === 'malicious').length;
  const totalBenign = samples.filter(s => s.label === 'benign').length;

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;

  const perCategory: DetailedResult['perCategory'] = {};
  for (const cat of CATEGORIES) {
    const s = catStats[cat];
    const catPrecision = s.tp + s.fp > 0 ? s.tp / (s.tp + s.fp) : 0;
    const catRecall = s.total > 0 ? s.detected / s.total : 0;
    const catF1 = catPrecision + catRecall > 0 ? 2 * (catPrecision * catRecall) / (catPrecision + catRecall) : 0;
    perCategory[cat] = {
      total: s.total,
      detected: s.detected,
      flagRate: s.total > 0 ? s.detected / s.total : 0,
      tp: s.tp,
      fp: s.fp,
      fn: s.fn,
      precision: catPrecision,
      recall: catRecall,
      f1: catF1,
    };
  }

  return {
    adapterId: adapter.id,
    adapterName: adapter.name,
    totalSamples: samples.length,
    totalMalicious,
    totalBenign,
    flagged,
    flagRate: flagged / samples.length,
    truePositives: tp,
    falsePositives: fp,
    trueNegatives: tn,
    falseNegatives: fn,
    precision: round(precision),
    recall: round(recall),
    f1: round(f1),
    fpr: round(fpr),
    avgScanTimeMs: results.length > 0 ? totalTimeMs / results.length : 0,
    perCategory,
  };
}

function round(n: number, d = 4): number {
  return Math.round(n * Math.pow(10, d)) / Math.pow(10, d);
}

function printDetailedResults(detailed: DetailedResult): void {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Scanner: ${detailed.adapterName} (${detailed.adapterId})`);
  console.log(`${'='.repeat(80)}`);
  console.log(`Samples: ${detailed.totalSamples} (${detailed.totalMalicious} malicious, ${detailed.totalBenign} benign)`);
  console.log(`Flagged: ${detailed.flagged} (${(detailed.flagRate * 100).toFixed(1)}% flag rate)`);
  console.log(`TP: ${detailed.truePositives}  FP: ${detailed.falsePositives}  FN: ${detailed.falseNegatives}  TN: ${detailed.trueNegatives}`);
  console.log(`Precision: ${(detailed.precision * 100).toFixed(1)}%  Recall: ${(detailed.recall * 100).toFixed(1)}%  F1: ${(detailed.f1 * 100).toFixed(1)}%  FPR: ${(detailed.fpr * 100).toFixed(2)}%`);
  if (detailed.avgScanTimeMs > 0) {
    console.log(`Avg scan time: ${detailed.avgScanTimeMs.toFixed(1)}ms`);
  }

  console.log(`\nPer-Category Breakdown:`);
  console.log(`${'Category'.padEnd(28)} | Total | Detected | Flag Rate | Precision | Recall | F1`);
  console.log('-'.repeat(95));

  for (const cat of CATEGORIES) {
    const c = detailed.perCategory[cat];
    if (c.total === 0 && c.fp === 0) continue;
    console.log(
      `${cat.padEnd(28)} | ${String(c.total).padEnd(5)} | ${String(c.detected).padEnd(8)} | ${(c.flagRate * 100).toFixed(1).padStart(5)}% | ${(c.precision * 100).toFixed(1).padStart(5)}% | ${(c.recall * 100).toFixed(1).padStart(5)}% | ${(c.f1 * 100).toFixed(1).padStart(5)}%`
    );
  }
}

function printUsage(): void {
  console.log(`OASB Benchmark Runner v2

Usage: npx tsx scripts/run-benchmark-v2.ts [options]

Options:
  --categorized-only   Exclude 225 registry stubs with no malicious content (recommended)
  --limit=N            Run on N samples (proportionally sampled)
  --adapter=ADAPTER    Run specific adapter: static, tme-only, pipeline, all (default: all)
  --help               Show this help

Examples:
  npx tsx scripts/run-benchmark-v2.ts --categorized-only              # Full benchmark (recommended)
  npx tsx scripts/run-benchmark-v2.ts --categorized-only --limit=100  # Quick test
  npx tsx scripts/run-benchmark-v2.ts --categorized-only --adapter=tme-only  # TME only

Note: Without --categorized-only, the corpus includes 225 registry metadata-flagged
stubs that contain no malicious content (just package names). These inflate false
negative counts. Use --categorized-only for results matching BENCHMARK-RESULTS.md.
`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printUsage();
    return;
  }

  const limitArg = args.find(a => a.startsWith('--limit='));
  const adapterArg = args.find(a => a.startsWith('--adapter='));
  const categorizedOnly = args.includes('--categorized-only');
  const limit = limitArg ? parseInt(limitArg.split('=')[1]) : undefined;
  const adapterFilter = adapterArg ? adapterArg.split('=')[1] : 'all';

  if (!categorizedOnly) {
    console.log('NOTE: Running without --categorized-only. Results will include 225 registry');
    console.log('stubs with no malicious content. Add --categorized-only for standard results.');
    console.log('');
  }

  // Load dataset
  const v2Path = join(__dirname, '..', 'corpus', 'v2.json');
  const dataset: BenchmarkDataset = JSON.parse(readFileSync(v2Path, 'utf-8'));

  let samples = dataset.samples;

  // Filter to categorized-only: excludes registry stubs labeled "malicious" with no
  // attack category and no actual malicious content. These are metadata-flagged,
  // not content-flagged, so a content scanner cannot meaningfully detect them.
  if (categorizedOnly) {
    samples = samples.filter(s =>
      s.label !== 'malicious' || (s.label === 'malicious' && s.category)
    );
    console.log(`[--categorized-only] Filtered to ${samples.length} samples with content-derived labels`);
  }

  if (limit) {
    // Keep proportional representation when limiting
    const malicious = samples.filter(s => s.label === 'malicious');
    const benign = samples.filter(s => s.label === 'benign');
    const edgeCase = samples.filter(s => s.label === 'edge_case');

    const malRatio = malicious.length / samples.length;
    const malLimit = Math.ceil(limit * malRatio);
    const benLimit = limit - malLimit;

    // Shuffle for randomness
    const shuffle = <T>(arr: T[]) => arr.sort(() => Math.random() - 0.5);
    samples = [
      ...shuffle(malicious).slice(0, malLimit),
      ...shuffle(benign).slice(0, benLimit),
      ...shuffle(edgeCase).slice(0, Math.min(edgeCase.length, Math.floor(limit * 0.02))),
    ];
  }

  console.log('OASB Skills Security Benchmark v2.0');
  console.log(`Dataset: ${samples.length} samples (${samples.filter(s => s.label === 'malicious').length} malicious, ${samples.filter(s => s.label === 'benign').length} benign, ${samples.filter(s => s.label === 'edge_case').length} edge)`);
  console.log(`Date: ${new Date().toISOString().split('T')[0]}`);
  console.log('');

  // Select adapters
  const adapters: ScannerAdapter[] = [];
  if (adapterFilter === 'all' || adapterFilter === 'static') {
    adapters.push(new HMAPipelineStaticAdapter());
  }
  if (adapterFilter === 'all' || adapterFilter === 'tme-only') {
    adapters.push(new HMATMEOnlyAdapter());
  }
  if (adapterFilter === 'all' || adapterFilter === 'pipeline') {
    adapters.push(new HMAPipelineAdapter());
  }

  console.log(`Running ${adapters.length} adapter(s)...\n`);

  const allDetailed: DetailedResult[] = [];

  for (const adapter of adapters) {
    const startTime = Date.now();
    const { detailed } = await runAdapter(adapter, samples);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`  [${adapter.id}] completed in ${elapsed}s`);
    allDetailed.push(detailed);
    printDetailedResults(detailed);
  }

  // Save results (use different filename for partial runs)
  const suffix = limit ? `-partial-${samples.length}` : '';
  const outputPath = join(__dirname, '..', `benchmark-results-v5${suffix}.json`);
  const output = {
    version: '2.0',
    date: new Date().toISOString(),
    datasetVersion: dataset.version,
    sampleCount: samples.length,
    adapters: Object.fromEntries(allDetailed.map(d => [d.adapterId, d])),
  };
  writeFileSync(outputPath, JSON.stringify(output, null, 2));
  console.log(`\nResults saved to ${outputPath}`);

  // Print comparison summary
  console.log(`\n${'='.repeat(80)}`);
  console.log('COMPARISON SUMMARY');
  console.log('='.repeat(80));
  console.log(`${'Scanner'.padEnd(42)} | F1     | Prec   | Recall | FPR    | Flag Rate`);
  console.log('-'.repeat(95));
  for (const d of allDetailed.sort((a, b) => b.f1 - a.f1)) {
    console.log(
      `${d.adapterName.padEnd(42)} | ${(d.f1 * 100).toFixed(1).padEnd(6)}% | ${(d.precision * 100).toFixed(1).padEnd(6)}% | ${(d.recall * 100).toFixed(1).padEnd(6)}% | ${(d.fpr * 100).toFixed(2).padEnd(6)}% | ${(d.flagRate * 100).toFixed(1)}%`
    );
  }
}

main().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
