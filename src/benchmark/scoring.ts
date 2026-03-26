/**
 * OASB Benchmark Scoring Engine
 *
 * Computes precision, recall, F1, FPR per attack category and in aggregate.
 * Assigns tier based on published thresholds.
 * Computes Cohen's Kappa vs HMA baseline.
 */

import {
  type AttackCategory,
  type AggregateMetrics,
  type BenchmarkSample,
  type BenchmarkTier,
  type CategoryMetrics,
  type LeaderboardEntry,
  type ScannerResult,
  type ScannerSubmission,
  ATTACK_CATEGORIES,
} from './types.js';

// ============================================================================
// Tier Thresholds
// ============================================================================

export interface TierThresholds {
  minF1: number;
  maxFPR: number;
  minCategoryCoverage: number; // out of 9
  minKappa?: number;           // vs HMA baseline
}

export const TIER_THRESHOLDS: Record<BenchmarkTier, TierThresholds> = {
  platinum: { minF1: 0.90, maxFPR: 0.05, minCategoryCoverage: 9, minKappa: 0.85 },
  gold:     { minF1: 0.80, maxFPR: 0.10, minCategoryCoverage: 7, minKappa: 0.70 },
  silver:   { minF1: 0.65, maxFPR: 0.20, minCategoryCoverage: 5 },
  listed:   { minF1: 0,    maxFPR: 1.0,  minCategoryCoverage: 0 },
  disqualified: { minF1: 0, maxFPR: 1.0, minCategoryCoverage: 0 },
};

// ============================================================================
// Scoring Engine
// ============================================================================

/**
 * Score a scanner submission against a labeled benchmark dataset.
 */
export function scoreSubmission(
  submission: ScannerSubmission,
  dataset: BenchmarkSample[],
  hmaBaseline?: ScannerSubmission,
): LeaderboardEntry {
  // Build lookup maps
  const sampleMap = new Map<string, BenchmarkSample>();
  for (const sample of dataset) {
    sampleMap.set(sample.id, sample);
  }

  const resultMap = new Map<string, ScannerResult>();
  for (const result of submission.results) {
    resultMap.set(result.sampleId, result);
  }

  // Compute per-category metrics
  const categoryMetrics = computeCategoryMetrics(sampleMap, resultMap);

  // Compute aggregate metrics
  const aggregate = computeAggregateMetrics(categoryMetrics);

  // Compute Cohen's Kappa vs HMA if baseline provided
  let kappa = 0;
  if (hmaBaseline) {
    const hmaResultMap = new Map<string, ScannerResult>();
    for (const result of hmaBaseline.results) {
      hmaResultMap.set(result.sampleId, result);
    }
    kappa = computeCohensKappa(resultMap, hmaResultMap, dataset);
  }

  aggregate.kappaVsHMA = kappa;

  // Determine tier
  const tier = determineTier(aggregate);

  return {
    scannerId: submission.scannerId,
    scannerName: submission.scannerName,
    scannerVersion: submission.scannerVersion,
    tier,
    metrics: aggregate,
    submittedAt: submission.submittedAt,
    datasetVersion: submission.datasetVersion,
    isHMABaseline: false,
  };
}

/**
 * Compute metrics per attack category.
 */
function computeCategoryMetrics(
  samples: Map<string, BenchmarkSample>,
  results: Map<string, ScannerResult>,
): CategoryMetrics[] {
  return ATTACK_CATEGORIES.map(category => {
    let tp = 0, fp = 0, tn = 0, fn = 0;

    for (const [sampleId, sample] of samples) {
      const result = results.get(sampleId);
      if (!result) {
        // Not scanned = treated as benign verdict
        if (sample.label === 'malicious' && sample.category === category) {
          fn++;
        } else if (sample.label === 'benign') {
          tn++;
        }
        continue;
      }

      const isMalicious = sample.label === 'malicious' && sample.category === category;
      const scannerSaysMalicious = result.verdict === 'malicious' && result.category === category;

      if (isMalicious && scannerSaysMalicious) tp++;
      else if (!isMalicious && scannerSaysMalicious) fp++;
      else if (isMalicious && !scannerSaysMalicious) fn++;
      else if (!isMalicious && !scannerSaysMalicious) tn++;
    }

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;

    return { category, truePositives: tp, falsePositives: fp, trueNegatives: tn, falseNegatives: fn, precision, recall, f1, fpr };
  });
}

/**
 * Compute aggregate metrics from per-category metrics.
 */
function computeAggregateMetrics(categories: CategoryMetrics[]): AggregateMetrics {
  // Macro-average across categories
  const nonEmpty = categories.filter(c => c.truePositives + c.falseNegatives > 0);
  const categoryCoverage = nonEmpty.filter(c => c.recall > 0).length;

  if (nonEmpty.length === 0) {
    return {
      precision: 0,
      recall: 0,
      f1: 0,
      fpr: 0,
      categoryCoverage: 0,
      kappaVsHMA: 0,
      categoryMetrics: categories,
    };
  }

  const avgPrecision = nonEmpty.reduce((sum, c) => sum + c.precision, 0) / nonEmpty.length;
  const avgRecall = nonEmpty.reduce((sum, c) => sum + c.recall, 0) / nonEmpty.length;
  const avgF1 = nonEmpty.reduce((sum, c) => sum + c.f1, 0) / nonEmpty.length;
  const avgFPR = categories.reduce((sum, c) => sum + c.fpr, 0) / categories.length;

  return {
    precision: round(avgPrecision, 4),
    recall: round(avgRecall, 4),
    f1: round(avgF1, 4),
    fpr: round(avgFPR, 4),
    categoryCoverage,
    kappaVsHMA: 0,
    categoryMetrics: categories,
  };
}

/**
 * Compute Cohen's Kappa agreement between two scanners.
 */
function computeCohensKappa(
  scanner1: Map<string, ScannerResult>,
  scanner2: Map<string, ScannerResult>,
  dataset: BenchmarkSample[],
): number {
  let agree = 0;
  let total = 0;
  let s1Mal = 0, s2Mal = 0;

  for (const sample of dataset) {
    const r1 = scanner1.get(sample.id);
    const r2 = scanner2.get(sample.id);
    if (!r1 || !r2) continue;

    total++;
    if (r1.verdict === r2.verdict) agree++;
    if (r1.verdict === 'malicious') s1Mal++;
    if (r2.verdict === 'malicious') s2Mal++;
  }

  if (total === 0) return 0;

  const po = agree / total; // observed agreement
  const p1 = s1Mal / total;
  const p2 = s2Mal / total;
  const pe = (p1 * p2) + ((1 - p1) * (1 - p2)); // expected agreement

  if (pe >= 1) return 1;
  return round((po - pe) / (1 - pe), 4);
}

/**
 * Determine benchmark tier from aggregate metrics.
 */
export function determineTier(metrics: AggregateMetrics): BenchmarkTier {
  const tiers: BenchmarkTier[] = ['platinum', 'gold', 'silver', 'listed'];

  for (const tier of tiers) {
    const thresholds = TIER_THRESHOLDS[tier];
    if (
      metrics.f1 >= thresholds.minF1 &&
      metrics.fpr <= thresholds.maxFPR &&
      metrics.categoryCoverage >= thresholds.minCategoryCoverage &&
      (!thresholds.minKappa || metrics.kappaVsHMA >= thresholds.minKappa)
    ) {
      return tier;
    }
  }

  return 'listed';
}

function round(n: number, decimals: number): number {
  const factor = Math.pow(10, decimals);
  return Math.round(n * factor) / factor;
}
