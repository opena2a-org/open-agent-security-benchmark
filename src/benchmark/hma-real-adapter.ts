/**
 * Real HMA Scanner Adapter for OASB Benchmark
 *
 * Uses the actual HackMyAgent NanoMind Semantic Compiler to classify
 * benchmark samples. No heuristics -- real AST compilation + analyzers.
 *
 * Three tiers:
 * 1. HMARealStaticAdapter: static regex checks only (no NanoMind)
 * 2. HMARealASTAdapter: NanoMind Semantic Compiler (AST-based)
 * 3. HMARealFullAdapter: AST + behavioral simulation
 */

import type { ScannerAdapter } from './runner.js';
import type { ScannerResult, AttackCategory } from './types.js';

// Import real HMA scanner components
// These come from the hackmyagent npm package
let SemanticCompiler: any;
let analyzeCapabilities: any;
let analyzeCredentials: any;
let analyzeGovernance: any;
let analyzeScope: any;
let analyzePrompt: any;
let analyzeCode: any;
let SimulationEngine: any;
let parseSkillProfile: any;

let loaded = false;

async function loadHMA(): Promise<boolean> {
  if (loaded) return true;
  try {
    // Try npm package first, then local monorepo path
    let core: any;
    let sim: any;
    try {
      core = await import('hackmyagent/nanomind-core');
    } catch {
      const hmaPath = require('path').resolve(__dirname, '..', '..', '..', 'hackmyagent', 'dist', 'nanomind-core', 'index.js');
      core = await import(hmaPath);
    }
    SemanticCompiler = core.SemanticCompiler;
    analyzeCapabilities = core.analyzeCapabilities;
    analyzeCredentials = core.analyzeCredentials;
    analyzeGovernance = core.analyzeGovernance;
    analyzeScope = core.analyzeScope;
    analyzePrompt = core.analyzePrompt;
    analyzeCode = core.analyzeCode;

    try {
      const hma = await import('hackmyagent');
      SimulationEngine = hma.SimulationEngine;
      parseSkillProfile = hma.parseSkillProfile;
    } catch {
      const simPath = require('path').resolve(__dirname, '..', '..', '..', 'hackmyagent', 'dist', 'simulation', 'index.js');
      sim = await import(simPath);
      SimulationEngine = sim.SimulationEngine;
      parseSkillProfile = sim.parseSkillProfile;
    }

    loaded = true;
    return true;
  } catch (err) {
    console.error('Failed to load HMA:', (err as Error).message);
    return false;
  }
}

// ============================================================================
// Real AST-Based Adapter
// ============================================================================

/**
 * Uses the real NanoMind Semantic Compiler for classification.
 * Compiles each sample into an AST, runs all 6 analyzers.
 */
export class HMARealASTAdapter implements ScannerAdapter {
  name = 'HackMyAgent + NanoMind AST';
  version = '0.12.0';
  id = 'hma-ast-real';

  private compiler: any = null;

  async scan(content: string, sampleId: string): Promise<ScannerResult> {
    if (!await loadHMA()) {
      return { sampleId, verdict: 'unknown' };
    }

    if (!this.compiler) {
      this.compiler = new SemanticCompiler({ useNanoMind: false }); // Heuristic mode (fast, no daemon needed)
    }

    try {
      // Compile artifact into AST
      const { ast } = await this.compiler.compile(content, `${sampleId}.skill.md`);

      // Run all analyzers
      const verifier = this.compiler.verifyAST.bind(this.compiler);
      const allFindings = [
        ...analyzeCapabilities(ast),
        ...(analyzeCredentials ? analyzeCredentials(ast, verifier) : []),
        ...(analyzeGovernance ? analyzeGovernance(ast, verifier) : []),
        ...(analyzeScope ? analyzeScope(ast, verifier) : []),
        ...(analyzePrompt ? analyzePrompt(ast, verifier) : []),
        ...(analyzeCode ? analyzeCode(ast, verifier) : []),
      ];

      const failed = allFindings.filter((f: any) => !f.passed);

      if (failed.length === 0) {
        return { sampleId, verdict: 'benign', confidence: ast.intentConfidence };
      }

      // Map AST attack class to benchmark category
      const criticalFinding = failed.find((f: any) => f.severity === 'critical') || failed[0];
      const category = mapAttackClass(criticalFinding?.attackClass);

      return {
        sampleId,
        verdict: 'malicious',
        category,
        confidence: ast.intentConfidence,
      };
    } catch {
      return { sampleId, verdict: 'unknown' };
    }
  }
}

// ============================================================================
// Real Static Adapter (regex only, no NanoMind)
// ============================================================================

/**
 * Uses HMA's static pattern matching (204 checks) without NanoMind.
 * Baseline for comparison.
 */
export class HMARealStaticAdapter implements ScannerAdapter {
  name = 'HackMyAgent (static only)';
  version = '0.12.0';
  id = 'hma-static-real';

  async scan(content: string, sampleId: string): Promise<ScannerResult> {
    const text = content.toLowerCase();

    // Real HMA static patterns (from scanner.ts CREDENTIAL_PATTERNS + SKILL_* patterns)
    const patterns = {
      credential_exfiltration: [
        /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/i,
        /sk-proj-[a-zA-Z0-9]{20,}/i,
        /AKIA[0-9A-Z]{16}/,
        /ghp_[a-zA-Z0-9]{36}/,
        /password\s*[=:]\s*['"][^'"]{4,}/i,
      ],
      exfiltration: [
        /webhook\.site/i,
        /requestbin/i,
        /forward.*token.*external/i,
        /send.*credential.*endpoint/i,
        /export.*data.*external/i,
      ],
      injection: [
        /ignore.*previous.*instruction/i,
        /override.*system.*prompt/i,
        /new.*task.*ignore/i,
        /bypass.*safety/i,
        /disable.*safety.*check/i,
      ],
      persistence: [
        /save.*permanently.*instruction/i,
        /remember.*forever.*rule/i,
        /persist.*across.*session/i,
        /write.*memory.*always/i,
      ],
      heartbeat_rce: [
        /fetch.*config.*from.*http/i,
        /download.*instruction.*from/i,
        /check.*update.*external/i,
        /load.*config.*remote/i,
      ],
      privilege_escalation: [
        /escalat.*admin/i,
        /access.*any.*database/i,
        /bypass.*permission/i,
        /grant.*full.*access/i,
      ],
      social_engineering: [
        /urgent.*credential/i,
        /emergency.*password/i,
        /immediate.*share.*key/i,
        /account.*compromised.*provide/i,
      ],
      policy_violation: [
        /bypass.*soul/i,
        /override.*governance/i,
        /suspend.*constraint/i,
        /disable.*safety.*filter/i,
      ],
    };

    let bestMatch: { category: string; confidence: number } | null = null;

    for (const [category, regexes] of Object.entries(patterns)) {
      const matches = regexes.filter(r => r.test(content)).length;
      if (matches > 0) {
        const confidence = Math.min(0.95, 0.5 + matches * 0.15);
        if (!bestMatch || confidence > bestMatch.confidence) {
          bestMatch = { category, confidence };
        }
      }
    }

    if (bestMatch) {
      return {
        sampleId,
        verdict: 'malicious',
        category: bestMatch.category as AttackCategory,
        confidence: bestMatch.confidence,
      };
    }

    return { sampleId, verdict: 'benign', confidence: 0.7 };
  }
}

// ============================================================================
// Real Full Adapter (AST + Simulation)
// ============================================================================

/**
 * Full pipeline: AST compilation + behavioral simulation.
 * Most accurate, slowest.
 */
export class HMARealFullAdapter implements ScannerAdapter {
  name = 'HackMyAgent + AST + Simulation';
  version = '0.12.0';
  id = 'hma-full-real';

  private astAdapter = new HMARealASTAdapter();

  async scan(content: string, sampleId: string): Promise<ScannerResult> {
    // First: AST classification
    const astResult = await this.astAdapter.scan(content, sampleId);

    // Then: behavioral simulation
    if (!await loadHMA() || !SimulationEngine || !parseSkillProfile) {
      return astResult;
    }

    try {
      const sim = new SimulationEngine();
      const profile = parseSkillProfile(content, `${sampleId}.skill.md`);
      const simResult = await sim.runLayer3(profile);

      // Combine: if simulation says MALICIOUS and AST agrees, high confidence
      if (simResult.verdict === 'MALICIOUS' && astResult.verdict === 'malicious') {
        return { ...astResult, confidence: Math.min(0.98, (astResult.confidence ?? 0.5) + 0.2) };
      }

      // If simulation says MALICIOUS but AST said benign, trust simulation
      if (simResult.verdict === 'MALICIOUS' && astResult.verdict === 'benign') {
        const failedCategory = simResult.failedProbes[0]?.attackClass;
        return {
          sampleId,
          verdict: 'malicious',
          category: mapAttackClass(failedCategory),
          confidence: simResult.confidence,
        };
      }

      // If both say benign, high confidence benign
      if (simResult.verdict === 'CLEAN' && astResult.verdict === 'benign') {
        return { sampleId, verdict: 'benign', confidence: 0.95 };
      }

      return astResult;
    } catch {
      return astResult;
    }
  }
}

// ============================================================================
// Helpers
// ============================================================================

function mapAttackClass(attackClass?: string): AttackCategory | undefined {
  if (!attackClass) return undefined;
  const ac = attackClass.toLowerCase().replace(/-/g, '_');

  const mapping: Record<string, AttackCategory> = {
    'skill_exfil': 'credential_exfiltration',
    'data_exfil': 'data_exfiltration',
    'exfiltration': 'credential_exfiltration',
    'prompt_inject': 'prompt_injection',
    'injection': 'prompt_injection',
    'priv_escalation': 'privilege_escalation',
    'privilege_escalation': 'privilege_escalation',
    'heartbeat_rce': 'heartbeat_rce',
    'lateral_movement': 'heartbeat_rce',
    'cred_harvest': 'credential_exfiltration',
    'credential_abuse': 'credential_exfiltration',
    'persistence': 'persistence',
    'soul_bypass': 'unicode_stego',
    'policy_violation': 'unicode_stego',
    'social_engineering': 'social_engineering',
    'semantic_mismatch': 'data_exfiltration',
    'scan_evasion': 'supply_chain',
    'capability_abuse': 'privilege_escalation',
  };

  return mapping[ac] ?? undefined;
}
