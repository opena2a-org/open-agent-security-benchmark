import { describe, it, expect } from 'vitest';
import { scoreSubmission, determineTier } from './scoring';
import { assessComplianceLevel } from './controls';
import type {
  BenchmarkSample,
  ScannerSubmission,
  AggregateMetrics,
} from './types';

// Helper: create a malicious sample
function malicious(id: string, category: string): BenchmarkSample {
  return {
    id,
    label: 'malicious',
    category: category as any,
    source: 'dvaa',
    version: 'v1.0',
    artifactType: 'skill',
    content: `malicious skill ${id}`,
  };
}

// Helper: create a benign sample
function benign(id: string): BenchmarkSample {
  return {
    id,
    label: 'benign',
    source: 'registry',
    version: 'v1.0',
    artifactType: 'skill',
    content: `benign skill ${id}`,
  };
}

describe('Benchmark Scoring Engine', () => {
  const dataset: BenchmarkSample[] = [
    malicious('m1', 'supply_chain'),
    malicious('m2', 'supply_chain'),
    malicious('m3', 'prompt_injection'),
    malicious('m4', 'credential_exfiltration'),
    benign('b1'),
    benign('b2'),
    benign('b3'),
  ];

  it('scores a perfect scanner as platinum', () => {
    const submission: ScannerSubmission = {
      scannerId: 'perfect-scanner',
      scannerName: 'Perfect Scanner',
      scannerVersion: '1.0',
      submittedAt: new Date().toISOString(),
      datasetVersion: 'v1.0',
      results: [
        { sampleId: 'm1', verdict: 'malicious', category: 'supply_chain' },
        { sampleId: 'm2', verdict: 'malicious', category: 'supply_chain' },
        { sampleId: 'm3', verdict: 'malicious', category: 'prompt_injection' },
        { sampleId: 'm4', verdict: 'malicious', category: 'credential_exfiltration' },
        { sampleId: 'b1', verdict: 'benign' },
        { sampleId: 'b2', verdict: 'benign' },
        { sampleId: 'b3', verdict: 'benign' },
      ],
    };

    const entry = scoreSubmission(submission, dataset);
    expect(entry.metrics.precision).toBe(1);
    expect(entry.metrics.recall).toBe(1);
    expect(entry.metrics.f1).toBe(1);
    expect(entry.metrics.fpr).toBe(0);
  });

  it('scores a scanner that misses everything as listed', () => {
    const submission: ScannerSubmission = {
      scannerId: 'blind-scanner',
      scannerName: 'Blind Scanner',
      scannerVersion: '1.0',
      submittedAt: new Date().toISOString(),
      datasetVersion: 'v1.0',
      results: [
        { sampleId: 'm1', verdict: 'benign' },
        { sampleId: 'm2', verdict: 'benign' },
        { sampleId: 'm3', verdict: 'benign' },
        { sampleId: 'm4', verdict: 'benign' },
        { sampleId: 'b1', verdict: 'benign' },
        { sampleId: 'b2', verdict: 'benign' },
        { sampleId: 'b3', verdict: 'benign' },
      ],
    };

    const entry = scoreSubmission(submission, dataset);
    expect(entry.metrics.recall).toBe(0);
    expect(entry.tier).toBe('listed');
  });

  it('penalizes high false positive rate', () => {
    const submission: ScannerSubmission = {
      scannerId: 'noisy-scanner',
      scannerName: 'Noisy Scanner',
      scannerVersion: '1.0',
      submittedAt: new Date().toISOString(),
      datasetVersion: 'v1.0',
      results: [
        { sampleId: 'm1', verdict: 'malicious', category: 'supply_chain' },
        { sampleId: 'm2', verdict: 'malicious', category: 'supply_chain' },
        { sampleId: 'm3', verdict: 'malicious', category: 'prompt_injection' },
        { sampleId: 'm4', verdict: 'malicious', category: 'credential_exfiltration' },
        // All benign flagged as malicious (false positives)
        { sampleId: 'b1', verdict: 'malicious', category: 'supply_chain' },
        { sampleId: 'b2', verdict: 'malicious', category: 'prompt_injection' },
        { sampleId: 'b3', verdict: 'malicious', category: 'credential_exfiltration' },
      ],
    };

    const entry = scoreSubmission(submission, dataset);
    expect(entry.metrics.recall).toBe(1); // catches everything
    expect(entry.metrics.fpr).toBeGreaterThan(0); // but lots of false positives
  });

  it('handles missing scanner results gracefully', () => {
    const submission: ScannerSubmission = {
      scannerId: 'partial-scanner',
      scannerName: 'Partial Scanner',
      scannerVersion: '1.0',
      submittedAt: new Date().toISOString(),
      datasetVersion: 'v1.0',
      results: [
        // Only scanned some samples
        { sampleId: 'm1', verdict: 'malicious', category: 'supply_chain' },
        { sampleId: 'b1', verdict: 'benign' },
      ],
    };

    const entry = scoreSubmission(submission, dataset);
    expect(entry).toBeTruthy();
    expect(entry.metrics.categoryCoverage).toBeGreaterThanOrEqual(0);
  });
});

describe('Tier Determination', () => {
  it('assigns platinum for perfect metrics', () => {
    const metrics: AggregateMetrics = {
      precision: 0.95,
      recall: 0.95,
      f1: 0.95,
      fpr: 0.02,
      categoryCoverage: 9,
      kappaVsHMA: 0.90,
      categoryMetrics: [],
    };
    expect(determineTier(metrics)).toBe('platinum');
  });

  it('assigns gold for good metrics', () => {
    const metrics: AggregateMetrics = {
      precision: 0.85,
      recall: 0.85,
      f1: 0.85,
      fpr: 0.08,
      categoryCoverage: 8,
      kappaVsHMA: 0.75,
      categoryMetrics: [],
    };
    expect(determineTier(metrics)).toBe('gold');
  });

  it('assigns silver for moderate metrics', () => {
    const metrics: AggregateMetrics = {
      precision: 0.70,
      recall: 0.70,
      f1: 0.70,
      fpr: 0.15,
      categoryCoverage: 6,
      kappaVsHMA: 0.5,
      categoryMetrics: [],
    };
    expect(determineTier(metrics)).toBe('silver');
  });

  it('assigns listed for poor metrics', () => {
    const metrics: AggregateMetrics = {
      precision: 0.30,
      recall: 0.30,
      f1: 0.30,
      fpr: 0.30,
      categoryCoverage: 3,
      kappaVsHMA: 0.2,
      categoryMetrics: [],
    };
    expect(determineTier(metrics)).toBe('listed');
  });
});

describe('Compliance Level Assessment', () => {
  it('returns none when no controls pass', () => {
    expect(assessComplianceLevel([])).toBe('none');
  });

  it('returns L1 when basic controls pass', () => {
    expect(assessComplianceLevel(['SS-01', 'SS-03', 'SS-04', 'SS-06', 'SEC-021'])).toBe('L1');
  });

  it('returns L2 when standard controls pass', () => {
    expect(assessComplianceLevel([
      'SS-01', 'SS-02', 'SS-03', 'SS-04', 'SS-05', 'SS-06', 'SS-07', 'SS-08', 'SEC-021',
    ])).toBe('L2');
  });

  it('returns L3 when all controls pass', () => {
    expect(assessComplianceLevel([
      'SS-01', 'SS-02', 'SS-03', 'SS-04', 'SS-05', 'SS-06', 'SS-07', 'SS-08', 'SS-09', 'SS-10', 'SEC-021',
    ])).toBe('L3');
  });

  it('returns L1 when only some L2 controls pass', () => {
    expect(assessComplianceLevel(['SS-01', 'SS-02', 'SS-03', 'SS-04', 'SS-06', 'SEC-021'])).toBe('L1');
  });

  it('returns none when SEC-021 is missing even if all SS controls pass', () => {
    expect(assessComplianceLevel([
      'SS-01', 'SS-03', 'SS-04', 'SS-06',
    ])).toBe('none');
  });
});
