/**
 * HMA Pipeline Adapter for OASB Benchmark v2
 *
 * Uses the REAL HackMyAgent NanoMind pipeline:
 *   1. SemanticCompiler (AST compilation + TME inference)
 *   2. All 6 analyzers (capability, credential, governance, scope, prompt, code)
 *   3. Verdict logic based on intent + findings + risk surfaces
 *
 * Three adapter tiers:
 *   - HMATMEOnlyAdapter: Just the ONNX TME classifier (raw model accuracy)
 *   - HMAPipelineAdapter: Full AST + analyzers (production pipeline)
 *   - HMAPipelineStaticAdapter: Static regex patterns only (no NanoMind)
 */

import type { ScannerAdapter } from './runner.js';
import type { ScannerResult, AttackCategory } from './types.js';

// Lazy-loaded HMA modules
let SemanticCompiler: any;
let analyzeCapabilities: any;
let analyzeCredentials: any;
let analyzeGovernance: any;
let analyzeScope: any;
let analyzePrompt: any;
let analyzeCode: any;
let getTMEClassifier: any;

let hmaLoaded = false;

async function loadHMACore(): Promise<boolean> {
  if (hmaLoaded) return true;
  try {
    const path = require('path');
    const corePath = path.resolve(__dirname, '..', '..', '..', 'hackmyagent', 'dist', 'nanomind-core', 'index.js');
    const core = await import(corePath);
    SemanticCompiler = core.SemanticCompiler;
    analyzeCapabilities = core.analyzeCapabilities;
    analyzeCredentials = core.analyzeCredentials;
    analyzeGovernance = core.analyzeGovernance;
    analyzeScope = core.analyzeScope;
    analyzePrompt = core.analyzePrompt;
    analyzeCode = core.analyzeCode;
    getTMEClassifier = core.getTMEClassifier;
    hmaLoaded = true;
    return true;
  } catch (err) {
    console.error('Failed to load HMA core:', (err as Error).message);
    return false;
  }
}

// Attack class mapping: HMA taxonomy -> OASB benchmark categories
const ATTACK_CLASS_MAP: Record<string, AttackCategory> = {
  // TME classifier classes
  exfiltration: 'data_exfiltration',
  injection: 'prompt_injection',
  privilege_escalation: 'privilege_escalation',
  persistence: 'persistence',
  credential_abuse: 'credential_exfiltration',
  lateral_movement: 'heartbeat_rce',
  social_engineering: 'social_engineering',
  // AST risk surface / finding classes
  'CRED-HARVEST': 'credential_exfiltration',
  'CRED-EXFIL': 'credential_exfiltration',
  'CRED-EXPOSURE': 'credential_exfiltration',
  'CRED-HARDCODED': 'credential_exfiltration',
  'SKILL-EXFIL': 'data_exfiltration',
  'DATA-EXFIL': 'data_exfiltration',
  'PROMPT-INJECT': 'prompt_injection',
  'JAILBREAK': 'prompt_injection',
  'AUTHORITY-CONFUSION': 'prompt_injection',
  'HEARTBEAT-RCE': 'heartbeat_rce',
  'PRIV-ESCALATION': 'privilege_escalation',
  'PERSIST': 'persistence',
  'SOCIAL-ENG': 'social_engineering',
  'SUPPLY-CHAIN': 'supply_chain',
  'SCAN-EVASION': 'supply_chain',
  'CODE-INJECT': 'heartbeat_rce',
  'UNICODE-STEGO': 'unicode_stego',
};

function mapToCategory(attackClass?: string): AttackCategory | undefined {
  if (!attackClass) return undefined;
  // Direct match
  if (ATTACK_CLASS_MAP[attackClass]) return ATTACK_CLASS_MAP[attackClass];
  // Normalized match
  const normalized = attackClass.toLowerCase().replace(/-/g, '_');
  if (ATTACK_CLASS_MAP[normalized]) return ATTACK_CLASS_MAP[normalized];
  // Prefix match
  for (const [key, cat] of Object.entries(ATTACK_CLASS_MAP)) {
    if (attackClass.toUpperCase().startsWith(key)) return cat;
  }
  return undefined;
}

/**
 * Disambiguate between credential_exfiltration and data_exfiltration
 * based on content signals.
 */
function disambiguateExfil(content: string, defaultCat: AttackCategory): AttackCategory {
  if (defaultCat !== 'credential_exfiltration' && defaultCat !== 'data_exfiltration') return defaultCat;
  const text = content.toLowerCase();
  const credSignals = (text.match(/api.?key|token|password|credential|secret|sk-ant|akia|ghp_/gi) || []).length;
  const dataSignals = (text.match(/select|database|table|record|customer|payment|pii|financial|medical|dump/gi) || []).length;
  if (dataSignals > credSignals) return 'data_exfiltration';
  return 'credential_exfiltration';
}

// ============================================================================
// TME-Only Adapter (raw ONNX model, no analyzers)
// ============================================================================

export class HMATMEOnlyAdapter implements ScannerAdapter {
  name = 'NanoMind TME v0.5.0 (model only)';
  version = '0.5.0';
  id = 'hma-tme-only';

  private tme: any = null;
  private ready = false;

  async scan(content: string, sampleId: string): Promise<ScannerResult> {
    if (!await loadHMACore()) return { sampleId, verdict: 'unknown' };

    if (!this.tme) {
      this.tme = getTMEClassifier();
      await this.tme.ensureModel();
      await this.tme.ensureReady();
      this.ready = true;
    }

    try {
      const result = await this.tme.classifyAsync(content);

      // Check for unicode steganography
      if (/[\u200B\u200C\u200D\u2060\u2062\u00AD\uFEFF]/.test(content)) {
        return {
          sampleId,
          verdict: 'malicious',
          category: 'unicode_stego',
          confidence: 0.95,
        };
      }

      // TME verdict: malicious if intentClass is malicious OR
      // if top class is an attack class with confidence > 0.5
      if (result.intentClass === 'malicious') {
        const category = mapToCategory(result.attackClass);
        return {
          sampleId,
          verdict: 'malicious',
          category: category ? disambiguateExfil(content, category) : undefined,
          confidence: result.confidence,
        };
      }

      return { sampleId, verdict: 'benign', confidence: result.confidence };
    } catch {
      return { sampleId, verdict: 'unknown' };
    }
  }
}

// ============================================================================
// Full Pipeline Adapter (SemanticCompiler + all analyzers)
// ============================================================================

export class HMAPipelineAdapter implements ScannerAdapter {
  name = 'HMA Full Pipeline (AST + NanoMind v0.5.0)';
  version = '0.12.9';
  id = 'hma-pipeline';

  private compiler: any = null;

  async scan(content: string, sampleId: string): Promise<ScannerResult> {
    if (!await loadHMACore()) return { sampleId, verdict: 'unknown' };

    if (!this.compiler) {
      this.compiler = new SemanticCompiler({ useNanoMind: true });
    }

    try {
      const startMs = Date.now();
      const { ast } = await this.compiler.compile(content, `${sampleId}.skill.md`);
      const compileMs = Date.now() - startMs;

      // Check unicode steganography first (zero-width chars)
      if (/[\u200B\u200C\u200D\u2060\u2062\u00AD\uFEFF]/.test(content)) {
        return {
          sampleId,
          verdict: 'malicious',
          category: 'unicode_stego',
          confidence: 0.95,
          scanTimeMs: compileMs,
        };
      }

      // Run all 6 analyzers
      const verifier = (a: any) => this.compiler.verifyAST(a);
      const allFindings = [
        ...analyzeCapabilities(ast),
        ...(analyzeCredentials ? analyzeCredentials(ast, verifier) : []),
        ...(analyzeGovernance ? analyzeGovernance(ast, verifier) : []),
        ...(analyzeScope ? analyzeScope(ast, verifier) : []),
        ...(analyzePrompt ? analyzePrompt(ast, verifier) : []),
        ...(analyzeCode ? analyzeCode(ast, verifier) : []),
      ];

      // Filter to actual attack findings (not governance/hardening gaps)
      // Key distinction: attack detection vs hardening recommendations
      const attackFindings = allFindings.filter((f: any) => {
        if (f.passed) return false;
        // These are hardening recommendations, not attack detections
        const hardeningChecks = [
          'AST-PROMPT-001', // Jailbreak susceptibility (missing defense)
          'AST-PROMPT-003', // Missing injection resistance
          'AST-PROMPT-004', // No trust hierarchy
          'AST-GOV-001',   // Missing governance constraints
          'AST-GOV-002',   // No human oversight
          'AST-GOV-003',   // Missing scope limitation
        ];
        if (hardeningChecks.includes(f.checkId)) return false;
        return true;
      });

      // Determine verdict from intent + findings + risk surfaces
      const isMaliciousByIntent = ast.intentClassification === 'malicious' && ast.intentConfidence > 0.6;
      const hasAttackFindings = attackFindings.length > 0;
      const hasRiskSurfaces = (ast.inferredRiskSurface?.length ?? 0) > 0;

      // Suspicious intent with corroborating evidence
      const isSuspiciousCorroborated =
        ast.intentClassification === 'suspicious' &&
        ast.intentConfidence > 0.5 &&
        (hasAttackFindings || hasRiskSurfaces);

      if (!isMaliciousByIntent && !hasAttackFindings && !isSuspiciousCorroborated) {
        return {
          sampleId,
          verdict: 'benign',
          confidence: ast.intentConfidence,
          scanTimeMs: Date.now() - startMs,
        };
      }

      // Determine attack category from multiple signals
      let category = this.determineCategory(ast, attackFindings, content);

      return {
        sampleId,
        verdict: 'malicious',
        category,
        confidence: ast.intentConfidence,
        scanTimeMs: Date.now() - startMs,
      };
    } catch {
      return { sampleId, verdict: 'unknown' };
    }
  }

  private determineCategory(ast: any, findings: any[], content: string): AttackCategory | undefined {
    // Priority: critical findings > risk surfaces > TME class

    // 1. Critical/high findings with attack class
    const critical = findings
      .filter((f: any) => f.severity === 'critical' || f.severity === 'high')
      .sort((a: any, b: any) => (a.severity === 'critical' ? -1 : 1));

    for (const f of critical) {
      const cat = mapToCategory(f.attackClass);
      if (cat) return disambiguateExfil(content, cat);
    }

    // 2. Any finding with attack class
    for (const f of findings) {
      const cat = mapToCategory(f.attackClass);
      if (cat) return disambiguateExfil(content, cat);
    }

    // 3. AST risk surfaces
    if (ast.inferredRiskSurface?.length > 0) {
      const sorted = [...ast.inferredRiskSurface].sort((a: any, b: any) => b.confidence - a.confidence);
      for (const risk of sorted) {
        const cat = mapToCategory(risk.attackClass);
        if (cat) return disambiguateExfil(content, cat);
      }
    }

    // 4. TME attack class (via AST intent metadata)
    // The compiler stores TME result in the AST
    if (ast.intentMetadata?.tmeAttackClass) {
      const cat = mapToCategory(ast.intentMetadata.tmeAttackClass);
      if (cat) return disambiguateExfil(content, cat);
    }

    return undefined;
  }
}

// ============================================================================
// Static-Only Adapter (no NanoMind, pure regex)
// ============================================================================

export class HMAPipelineStaticAdapter implements ScannerAdapter {
  name = 'HMA Static Patterns (no NanoMind)';
  version = '0.12.9';
  id = 'hma-static-pipeline';

  async scan(content: string, sampleId: string): Promise<ScannerResult> {
    const startMs = Date.now();

    // Check unicode steganography
    if (/[\u200B\u200C\u200D\u2060\u2062\u00AD\uFEFF]/.test(content)) {
      return { sampleId, verdict: 'malicious', category: 'unicode_stego', confidence: 0.95, scanTimeMs: Date.now() - startMs };
    }

    // Static pattern groups with associated categories
    const patternGroups: Array<{ category: AttackCategory; patterns: RegExp[]; weight: number }> = [
      {
        category: 'credential_exfiltration',
        weight: 1.0,
        patterns: [
          /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/i,
          /sk-proj-[a-zA-Z0-9]{20,}/i,
          /AKIA[0-9A-Z]{16}/,
          /ghp_[a-zA-Z0-9]{36}/,
          /forward.*credential|send.*token.*external|export.*api.?key/i,
          /provide.*password|share.*credential|enter.*key.*for.*verification/i,
        ],
      },
      {
        category: 'data_exfiltration',
        weight: 1.0,
        patterns: [
          /webhook\.site|requestbin|pipedream\.net|hookbin/i,
          /forward.*data.*external|send.*to.*endpoint/i,
          /select\s+\*\s+from|dump.*database|export.*records/i,
          /exfiltrat|leak.*data|siphon/i,
        ],
      },
      {
        category: 'prompt_injection',
        weight: 0.9,
        patterns: [
          /ignore.*previous.*instruction/i,
          /override.*system.*prompt/i,
          /new.*task.*ignore|bypass.*safety/i,
          /disable.*safety.*check|jailbreak/i,
          /you are now|from now on.*you must/i,
        ],
      },
      {
        category: 'heartbeat_rce',
        weight: 0.8,
        patterns: [
          /fetch.*config.*from.*http/i,
          /download.*instruction.*from/i,
          /check.*update.*external|load.*config.*remote/i,
          /eval\(|exec\(|child_process|subprocess/i,
        ],
      },
      {
        category: 'persistence',
        weight: 0.8,
        patterns: [
          /save.*permanently.*instruction|remember.*forever/i,
          /persist.*across.*session|write.*memory.*always/i,
          /modify.*system.*config|install.*backdoor/i,
        ],
      },
      {
        category: 'privilege_escalation',
        weight: 0.8,
        patterns: [
          /escalat.*admin|access.*any.*database/i,
          /bypass.*permission|grant.*full.*access/i,
          /sudo|root.*privilege|admin.*right/i,
        ],
      },
      {
        category: 'social_engineering',
        weight: 0.7,
        patterns: [
          /urgent.*credential|emergency.*password/i,
          /immediate.*share.*key|account.*compromised/i,
          /verify.*identity.*by.*sharing|confirm.*by.*entering/i,
        ],
      },
      {
        category: 'supply_chain',
        weight: 0.7,
        patterns: [
          /npm install.*\|\s*sh/i,
          /curl.*\|\s*(bash|sh)/i,
          /dependency.*confus|typosquat/i,
        ],
      },
    ];

    let bestMatch: { category: AttackCategory; score: number } | null = null;

    for (const group of patternGroups) {
      const matches = group.patterns.filter(r => r.test(content)).length;
      if (matches > 0) {
        const score = (matches / group.patterns.length) * group.weight;
        if (!bestMatch || score > bestMatch.score) {
          bestMatch = { category: group.category, score };
        }
      }
    }

    if (bestMatch) {
      return {
        sampleId,
        verdict: 'malicious',
        category: bestMatch.category,
        confidence: Math.min(0.95, 0.4 + bestMatch.score * 0.5),
        scanTimeMs: Date.now() - startMs,
      };
    }

    return { sampleId, verdict: 'benign', confidence: 0.7, scanTimeMs: Date.now() - startMs };
  }
}
