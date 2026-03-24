// Re-export OASB-native types from the adapter interface
// Tests should import from here or from './adapter'
export type {
  SecurityEvent,
  EnforcementResult,
  AlertRule,
  AlertCondition,
  EventCategory,
  EventSeverity,
  MonitorSource,
  EnforcementAction,
  ScanResult,
  ScanMatch,
  ThreatPattern,
  BudgetStatus,
  LLMAdapter,
  LLMResponse,
  LabConfig,
  SecurityProductAdapter,
  PromptScanner,
  MCPScanner,
  A2AScanner,
  PatternScanner,
  BudgetManager,
  AnomalyScorer,
  EventEngine,
  EnforcementEngine,
  Capability,
  CapabilityMatrix,
} from './adapter';

/** Annotation metadata for test cases */
export interface TestAnnotation {
  /** Is this scenario an actual attack? */
  isAttack: boolean;
  /** MITRE ATLAS technique ID */
  atlasId?: string;
  /** OWASP Agentic Top 10 category */
  owaspId?: string;
  /** Whether the product should detect this */
  expectedDetection: boolean;
  /** Expected minimum severity if detected */
  expectedSeverity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Timestamp when the attack was initiated */
  attackTimestamp?: number;
}

/** Collected test result with timing info */
export interface TestResult {
  testId: string;
  annotation: TestAnnotation;
  detected: boolean;
  detectionTimeMs?: number;
  events: import('./adapter').SecurityEvent[];
  enforcements: import('./adapter').EnforcementResult[];
}

/** Suite-level metrics */
export interface SuiteMetrics {
  totalTests: number;
  attacks: number;
  benign: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  detectionRate: number;
  falsePositiveRate: number;
  meanDetectionTimeMs: number;
  p95DetectionTimeMs: number;
}
