#!/usr/bin/env npx tsx
/**
 * ARP Lab Report Generator
 *
 * Reads vitest JSON output and generates a markdown report with:
 * - Test pass/fail summary
 * - MITRE ATLAS coverage table
 * - OWASP Agentic Top 10 coverage table
 * - Detection metrics (if annotations present)
 */

import * as fs from 'fs';
import * as path from 'path';

interface VitestResult {
  numTotalTests: number;
  numPassedTests: number;
  numFailedTests: number;
  numPendingTests: number;
  testResults: Array<{
    name: string;
    status: 'passed' | 'failed' | 'skipped';
    assertionResults: Array<{
      fullName: string;
      status: 'passed' | 'failed' | 'skipped';
      duration: number;
    }>;
  }>;
}

// ATLAS mapping from test IDs
const ATLAS_MAP: Record<string, { technique: string; description: string }> = {
  'AT-PROC-001': { technique: 'AML.T0046', description: 'Unsafe inference spawns child process' },
  'AT-PROC-002': { technique: 'AML.T0046', description: 'Suspicious binary execution (curl/wget)' },
  'AT-PROC-003': { technique: 'AML.T0029', description: 'Denial of service via CPU exhaustion' },
  'AT-PROC-004': { technique: 'AML.T0046', description: 'Privilege escalation via root process' },
  'AT-PROC-005': { technique: 'AML.TA0006', description: 'Process termination in attack lifecycle' },
  'AT-NET-001': { technique: 'AML.T0024', description: 'Exfiltration via new outbound connection' },
  'AT-NET-002': { technique: 'AML.T0057', description: 'Data leakage to known-bad host' },
  'AT-NET-003': { technique: 'AML.T0029', description: 'Connection burst denial of service' },
  'AT-NET-004': { technique: 'AML.T0024', description: 'Allowed host bypass via subdomain' },
  'AT-NET-005': { technique: 'AML.T0057', description: 'Exfiltration to known destinations' },
  'AT-FS-001': { technique: 'AML.T0057', description: 'Sensitive credential file access' },
  'AT-FS-002': { technique: 'AML.T0046', description: 'File access outside allowed paths' },
  'AT-FS-003': { technique: 'AML.T0057', description: 'Credential file access detection' },
  'AT-FS-004': { technique: 'AML.T0029', description: 'Mass file creation DoS' },
  'AT-FS-005': { technique: 'AML.T0018', description: 'Persistence via shell config modification' },
  'AT-INT-001': { technique: 'AML.T0054', description: 'L0 rule-based threat classification' },
  'AT-INT-002': { technique: 'AML.T0015', description: 'L1 statistical anomaly scoring' },
  'AT-INT-003': { technique: 'AML.T0054', description: 'L2 LLM escalation deferral' },
  'AT-INT-004': { technique: 'AML.T0029', description: 'Budget exhaustion denial of service' },
  'AT-INT-005': { technique: 'AML.T0015', description: 'Baseline learning and evasion detection' },
  'AT-ENF-001': { technique: 'AML.TA0006', description: 'Log enforcement action' },
  'AT-ENF-002': { technique: 'AML.TA0006', description: 'Alert callback execution' },
  'AT-ENF-003': { technique: 'AML.TA0006', description: 'Process pause via SIGSTOP' },
  'AT-ENF-004': { technique: 'AML.TA0006', description: 'Process kill via SIGTERM' },
  'AT-ENF-005': { technique: 'AML.TA0006', description: 'Process resume via SIGCONT' },
  'INT-001': { technique: 'AML.T0057', description: 'End-to-end data exfiltration chain' },
  'INT-002': { technique: 'AML.T0056', description: 'MCP plugin compromise chain' },
  'INT-003': { technique: 'AML.T0051', description: 'Prompt injection with anomaly detection' },
  'INT-004': { technique: 'AML.T0024', description: 'A2A trust exploitation' },
  'INT-005': { technique: 'AML.T0015', description: 'Evasion via slow baseline poisoning' },
  'INT-006': { technique: 'AML.T0046', description: 'Multi-monitor event correlation' },
  'INT-007': { technique: 'AML.T0029', description: 'Budget exhaustion denial of service' },
  'INT-008': { technique: 'AML.TA0006', description: 'Kill switch defensive response' },
  'BL-001': { technique: 'N/A', description: 'Normal agent profile (false positive check)' },
  'BL-002': { technique: 'AML.T0015', description: 'Controlled anomaly injection' },
  'BL-003': { technique: 'AML.T0015', description: 'Baseline persistence gap documentation' },
};

const OWASP_MAP: Record<string, string> = {
  'A01': 'Prompt Injection',
  'A04': 'Excessive Agency',
  'A06': 'Excessive Consumption',
  'A07': 'System Prompt Leakage',
};

function extractTestId(filename: string): string | null {
  const match = filename.match(/(AT-\w+-\d+|INT-\d+|BL-\d+)/);
  return match ? match[1] : null;
}

function generateReport(resultsPath?: string): string {
  let results: VitestResult | null = null;

  if (resultsPath && fs.existsSync(resultsPath)) {
    try {
      results = JSON.parse(fs.readFileSync(resultsPath, 'utf-8'));
    } catch {
      // Fall through to static report
    }
  }

  const lines: string[] = [];
  const now = new Date().toISOString().split('T')[0];

  lines.push('# ARP Lab Test Report');
  lines.push(`\nGenerated: ${now}`);
  lines.push('');

  // Summary
  if (results) {
    lines.push('## Summary');
    lines.push('');
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Total Tests | ${results.numTotalTests} |`);
    lines.push(`| Passed | ${results.numPassedTests} |`);
    lines.push(`| Failed | ${results.numFailedTests} |`);
    lines.push(`| Skipped | ${results.numPendingTests} |`);
    lines.push(`| Pass Rate | ${((results.numPassedTests / results.numTotalTests) * 100).toFixed(1)}% |`);
    lines.push('');
  }

  // ATLAS Coverage
  lines.push('## MITRE ATLAS Coverage');
  lines.push('');
  lines.push('| Test ID | ATLAS Technique | Description | Status |');
  lines.push('|---------|----------------|-------------|--------|');

  for (const [testId, mapping] of Object.entries(ATLAS_MAP)) {
    let status = 'N/A';
    if (results) {
      const testFile = results.testResults.find((r) => r.name.includes(testId));
      status = testFile ? (testFile.status === 'passed' ? 'PASS' : 'FAIL') : 'N/A';
    }
    lines.push(`| ${testId} | ${mapping.technique} | ${mapping.description} | ${status} |`);
  }
  lines.push('');

  // ATLAS Technique Coverage
  const techniques = new Set(Object.values(ATLAS_MAP).map((m) => m.technique).filter((t) => t !== 'N/A'));
  lines.push(`**Unique ATLAS techniques covered:** ${techniques.size}`);
  lines.push('');

  // OWASP Mapping
  lines.push('## OWASP Agentic Top 10 Coverage');
  lines.push('');
  lines.push('| OWASP ID | Category | Tests |');
  lines.push('|----------|----------|-------|');
  for (const [id, name] of Object.entries(OWASP_MAP)) {
    lines.push(`| ${id} | ${name} | See mapping docs |`);
  }
  lines.push('');

  // Known Gaps
  lines.push('## Known Gaps (Documented)');
  lines.push('');
  lines.push('| # | Gap | Severity | Test Coverage |');
  lines.push('|---|-----|----------|--------------|');
  lines.push('| 6 | Anomaly baselines not persisted across restarts | Medium | BL-003 |');
  lines.push('| 7 | No connection rate anomaly detection | Medium | AT-NET-003 |');
  lines.push('| 8 | No HTTP response/output monitoring | Arch | INT-003 |');
  lines.push('| 9 | No event correlation across monitors | Arch | INT-006 |');
  lines.push('');

  return lines.join('\n');
}

// Main
const resultsPath = process.argv[2] || path.join(process.cwd(), 'test-results.json');
const report = generateReport(resultsPath);
const outputPath = path.join(process.cwd(), 'REPORT.md');
fs.writeFileSync(outputPath, report);
console.log(`Report written to ${outputPath}`);
