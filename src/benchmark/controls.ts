/**
 * OASB Skills Security Track -- SS-01 through SS-10, SEC-021
 *
 * Controls for skill supply chain security plus policy enforcement.
 * Maps to compliance levels: L1 (Basic), L2 (Standard), L3 (Advanced).
 */

export interface RegulatoryMapping {
  framework: 'NIST AI RMF' | 'SOC 2' | 'ISO 27001' | 'EU AI Act' | 'CISA AI Security';
  reference: string;
}

export interface EvidenceTier {
  tier: 'T1' | 'T2' | 'T3';
  description: string;
  requires: string[];
  attestationLevel: 'L1' | 'L2' | 'L3';
}

export interface SkillSecurityControl {
  id: string;
  name: string;
  description: string;
  complianceLevel: 'L1' | 'L2' | 'L3';
  mapsTo: string[]; // HMA check IDs or attack classes
  verificationMethod: string;
  regulatoryMappings?: RegulatoryMapping[];
  evidenceTiers?: EvidenceTier[];
}

export const SKILL_SECURITY_CONTROLS: SkillSecurityControl[] = [
  {
    id: 'SS-01',
    name: 'Skill Source Verification',
    description: 'Verify skill provenance: publisher identity, registry presence, signature validity',
    complianceLevel: 'L1',
    mapsTo: ['SUPPLY-001', 'SUPPLY-002', 'SUPPLY-003', 'SUPPLY-004', 'SUPPLY-005', 'SUPPLY-006', 'SUPPLY-007', 'SUPPLY-008'],
    verificationMethod: 'Check publisher verification status in Registry, validate signature chain',
  },
  {
    id: 'SS-02',
    name: 'Static Malicious Pattern Detection',
    description: 'Scan skill source for known malicious patterns across all 9 attack categories',
    complianceLevel: 'L2',
    mapsTo: ['HMA Benchmark Score >= Silver tier'],
    verificationMethod: 'Run HMA scan, verify benchmark tier rating >= Silver',
  },
  {
    id: 'SS-03',
    name: 'UNICODE Steganography Detection',
    description: 'Explicit check for invisible codepoints, bidi overrides, homoglyphs in skill source',
    complianceLevel: 'L1',
    mapsTo: ['UNICODE-STEGO'],
    verificationMethod: 'HMA UNICODE-STEGO checks pass with no findings',
  },
  {
    id: 'SS-04',
    name: 'Heartbeat URL Security',
    description: 'Validate heartbeat URLs are registered, signed, and point to verified endpoints',
    complianceLevel: 'L1',
    mapsTo: ['HEARTBEAT-RCE'],
    verificationMethod: 'All heartbeat URLs resolve to registered domains with valid TLS',
  },
  {
    id: 'SS-05',
    name: 'Capability Declaration Completeness',
    description: 'Require complete capability manifests before skill installation. No undeclared tool access.',
    complianceLevel: 'L2',
    mapsTo: ['ARP capability manifest enforcement'],
    verificationMethod: 'ARP capability manifest exists and covers all observed capabilities',
  },
  {
    id: 'SS-06',
    name: 'Skill Trust Score Threshold',
    description: 'Registry trust score >= configurable threshold before installation allowed',
    complianceLevel: 'L1',
    mapsTo: ['Registry crowdsourced trust score'],
    verificationMethod: 'Trust score >= 60 (L1), >= 75 (L2), >= 85 (L3)',
  },
  {
    id: 'SS-07',
    name: 'Post-Install Behavioral Baseline',
    description: 'ARP behavioral baseline established within 24h of skill installation. Anomaly detection active.',
    complianceLevel: 'L2',
    mapsTo: ['ARP runtime behavioral twin'],
    verificationMethod: 'ARP baseline file exists for installed skill, anomaly threshold active',
  },
  {
    id: 'SS-08',
    name: 'Rug Pull Protection',
    description: 'Skill content hash verified against Registry on each invocation. Detects post-install modification.',
    complianceLevel: 'L2',
    mapsTo: ['Skill Monitor daemon'],
    verificationMethod: 'Content hash matches Registry record on every invocation',
  },
  {
    id: 'SS-09',
    name: 'Scanner Coverage Requirement',
    description: 'At least one Platinum or Gold benchmark-rated scanner must have scanned the skill',
    complianceLevel: 'L3',
    mapsTo: ['Leaderboard tier integration'],
    verificationMethod: 'Registry API confirms scanner consensus from benchmark-rated scanners',
  },
  {
    id: 'SS-10',
    name: 'Skill Lifecycle Management',
    description: 'Unused skills removed within 30 days, version pinning enforced, update approval workflow',
    complianceLevel: 'L3',
    mapsTo: ['Lifecycle governance'],
    verificationMethod: 'No unused skills > 30 days, all versions pinned, update approvals logged',
  },
  {
    id: 'SEC-021',
    name: 'Policy Enforcement Fail-Closed Semantics',
    description:
      'Policy enforcement must DENY on unresolvable inputs. No threshold-based fallbacks, no ask-user escalation, no silent bypass. Parse failures produce DENY with POLICY_PARSE_FAILURE event. Aligned with OPENA2A-IB-007 (Threshold Bypass).',
    complianceLevel: 'L1',
    mapsTo: ['PEI-001', 'PEI-002', 'PEI-003', 'CR-001', 'CR-002'],
    verificationMethod:
      'T1: docs declare parse-to-deny semantics. T2: PEI-001 + PEI-003 scans pass. T3: POLICY_PARSE_FAILURE log clean over attestation window.',
    regulatoryMappings: [
      { framework: 'NIST AI RMF', reference: 'GOVERN 1.6' },
      { framework: 'NIST AI RMF', reference: 'MANAGE 2.2' },
      { framework: 'NIST AI RMF', reference: 'MEASURE 2.5' },
      { framework: 'SOC 2', reference: 'CC6.1' },
      { framework: 'ISO 27001', reference: 'A.8.20' },
      { framework: 'EU AI Act', reference: 'Art. 9' },
      { framework: 'CISA AI Security', reference: 'Section 3.2' },
    ],
    evidenceTiers: [
      {
        tier: 'T1',
        description: 'Documented parse-to-deny enforcement semantics in enforcement architecture docs',
        requires: ['docs/architecture/arp-enforcement.md'],
        attestationLevel: 'L1',
      },
      {
        tier: 'T2',
        description: 'Static scan evidence: PEI-001 (threshold fallback detection) and PEI-003 (ask-user escalation detection) pass with no findings',
        requires: ['PEI-001', 'PEI-003'],
        attestationLevel: 'L2',
      },
      {
        tier: 'T3',
        description: 'Runtime evidence: POLICY_PARSE_FAILURE event log shows no uncontained parse failures over the attestation window',
        requires: ['POLICY_PARSE_FAILURE telemetry stream', 'Attestation window >= 30 days'],
        attestationLevel: 'L3',
      },
    ],
  },
];

/** Map compliance level to required controls */
export const COMPLIANCE_LEVELS = {
  L1: ['SS-01', 'SS-03', 'SS-04', 'SS-06', 'SEC-021'],
  L2: ['SS-01', 'SS-02', 'SS-03', 'SS-04', 'SS-05', 'SS-06', 'SS-07', 'SS-08', 'SEC-021'],
  L3: ['SS-01', 'SS-02', 'SS-03', 'SS-04', 'SS-05', 'SS-06', 'SS-07', 'SS-08', 'SS-09', 'SS-10', 'SEC-021'],
};

/**
 * Check which compliance level an agent achieves based on passing controls.
 */
export function assessComplianceLevel(passingControls: string[]): 'L3' | 'L2' | 'L1' | 'none' {
  const passing = new Set(passingControls);

  if (COMPLIANCE_LEVELS.L3.every(id => passing.has(id))) return 'L3';
  if (COMPLIANCE_LEVELS.L2.every(id => passing.has(id))) return 'L2';
  if (COMPLIANCE_LEVELS.L1.every(id => passing.has(id))) return 'L1';
  return 'none';
}
