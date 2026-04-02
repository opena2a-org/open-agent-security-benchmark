/**
 * DEPRECATED: Use run-benchmark-v2.ts instead.
 *
 *   npx tsx scripts/run-benchmark-v2.ts --categorized-only
 *
 * This v1 runner used heuristic adapters against the v1 corpus (90 samples).
 * It is kept for reference but may not work with current HMA versions.
 */

console.error('This script is deprecated. Use run-benchmark-v2.ts instead:');
console.error('  npx tsx scripts/run-benchmark-v2.ts --categorized-only');
process.exit(1);

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  HMAStaticAdapter,
  HMASemanticAdapter,
  HMASimulationAdapter,
  runBenchmark,
  formatComparisonTable,
} from '../src/benchmark/runner.js';
import { HMARealStaticAdapter, HMARealASTAdapter } from '../src/benchmark/hma-real-adapter.js';
import type { BenchmarkDataset } from '../src/benchmark/types.js';

async function main() {
  // Load dataset
  // Use v2 if available, fall back to v1
  const fs = await import('node:fs');
  const v2Path = join(__dirname, '..', 'corpus', 'v2.json');
  const v1Path = join(__dirname, '..', 'corpus', 'v1.json');
  const datasetPath = fs.existsSync(v2Path) ? v2Path : v1Path;
  const dataset: BenchmarkDataset = JSON.parse(readFileSync(datasetPath, 'utf-8'));

  console.log(`OASB Skills Security Benchmark v1.0`);
  console.log(`Dataset: ${dataset.totalSamples} samples (${dataset.maliciousSamples} malicious, ${dataset.benignSamples} benign, ${dataset.edgeCaseSamples} edge cases)`);
  console.log('');

  // Run all adapters (HMA Semantic first as baseline for Cohen's Kappa)
  const adapters = [
    new HMASemanticAdapter(),
    new HMAStaticAdapter(),
    new HMASimulationAdapter(),
    new HMARealStaticAdapter(),
    new HMARealASTAdapter(),
  ];

  const result = await runBenchmark(dataset.samples, adapters);

  console.log(formatComparisonTable(result));
  console.log('');

  // Print per-category breakdown for each adapter
  for (const [id, entry] of result.scannerResults) {
    console.log(`\n--- ${entry.scannerName} (${entry.tier.toUpperCase()}) ---`);
    console.log(`  F1=${entry.metrics.f1.toFixed(3)} Prec=${entry.metrics.precision.toFixed(3)} Recall=${entry.metrics.recall.toFixed(3)} FPR=${(entry.metrics.fpr * 100).toFixed(1)}% Kappa=${entry.metrics.kappaVsHMA.toFixed(3)} Cats=${entry.metrics.categoryCoverage}/9`);
    for (const cat of entry.metrics.categoryMetrics) {
      if (cat.truePositives > 0 || cat.falseNegatives > 0) {
        console.log(`  ${cat.category.padEnd(25)} TP=${cat.truePositives} FP=${cat.falsePositives} FN=${cat.falseNegatives} F1=${cat.f1.toFixed(2)}`);
      }
    }
  }
}

main().catch(console.error);
