/**
 * OASB Skills Security Track -- Type definitions
 *
 * Ground-truth labeled dataset format, scoring methodology,
 * and leaderboard tier system.
 */

// ============================================================================
// Dataset Types
// ============================================================================

/** The 9 attack categories for benchmark evaluation */
export type AttackCategory =
  | 'supply_chain'
  | 'prompt_injection'
  | 'credential_exfiltration'
  | 'heartbeat_rce'
  | 'unicode_stego'
  | 'privilege_escalation'
  | 'persistence'
  | 'social_engineering'
  | 'data_exfiltration';

export const ATTACK_CATEGORIES: AttackCategory[] = [
  'supply_chain',
  'prompt_injection',
  'credential_exfiltration',
  'heartbeat_rce',
  'unicode_stego',
  'privilege_escalation',
  'persistence',
  'social_engineering',
  'data_exfiltration',
];

/** Ground truth label for a benchmark sample */
export type GroundTruthLabel = 'malicious' | 'benign' | 'edge_case';

/** A single labeled sample in the benchmark dataset */
export interface BenchmarkSample {
  id: string;
  label: GroundTruthLabel;
  category?: AttackCategory;         // only for malicious samples
  confidence?: number;                // 0-1, only for edge_case samples
  source: 'dvaa' | 'hma_payload' | 'aria' | 'registry' | 'enterprise' | 'expert_consensus';
  version: string;                    // dataset version (e.g., "v1.0")
  artifactType: 'skill' | 'soul' | 'mcp_tool' | 'system_prompt' | 'agent_config';
  content: string;                    // the artifact text
  verificationScript?: string;        // path to verify.py for reproducible ground truth
  metadata?: Record<string, unknown>;
}

/** The full benchmark dataset */
export interface BenchmarkDataset {
  version: string;
  createdAt: string;
  totalSamples: number;
  maliciousSamples: number;
  benignSamples: number;
  edgeCaseSamples: number;
  categoryCounts: Record<AttackCategory, number>;
  samples: BenchmarkSample[];
}

// ============================================================================
// Scoring Types
// ============================================================================

/** Per-category scoring metrics */
export interface CategoryMetrics {
  category: AttackCategory;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;     // TP / (TP + FP)
  recall: number;        // TP / (TP + FN)
  f1: number;            // 2 * (P * R) / (P + R)
  fpr: number;           // FP / (FP + TN)
}

/** Aggregate scoring metrics */
export interface AggregateMetrics {
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  categoryCoverage: number;      // categories detected / 9
  kappaVsHMA: number;            // Cohen's Kappa vs HMA baseline
  categoryMetrics: CategoryMetrics[];
}

/** Leaderboard tier based on aggregate metrics */
export type BenchmarkTier = 'platinum' | 'gold' | 'silver' | 'listed' | 'disqualified';

/** Scanner submission result */
export interface ScannerSubmission {
  scannerId: string;
  scannerName: string;
  scannerVersion: string;
  submittedAt: string;
  datasetVersion: string;
  results: ScannerResult[];
}

/** Individual scan result for a benchmark sample */
export interface ScannerResult {
  sampleId: string;
  verdict: 'malicious' | 'benign' | 'unknown';
  category?: AttackCategory;
  confidence?: number;
  scanTimeMs?: number;
}

/** Leaderboard entry for a scored scanner */
export interface LeaderboardEntry {
  scannerId: string;
  scannerName: string;
  scannerVersion: string;
  tier: BenchmarkTier;
  metrics: AggregateMetrics;
  submittedAt: string;
  datasetVersion: string;
  isHMABaseline: boolean;
}
