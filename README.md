# ARP Lab

Comprehensive runtime security testing lab for [ARP](https://github.com/opena2a-org/opena2a-arp) (Agent Runtime Protection). Exercises every ARP capability against realistic attack scenarios, maps tests to MITRE ATLAS and OWASP Agentic Top 10, and reports detection effectiveness metrics.

## Quick Start

```bash
# Clone and install
git clone https://github.com/opena2a-org/arp-lab.git
cd arp-lab
npm install

# Run atomic tests (no external dependencies)
npm run test:atomic

# Run integration tests (requires DVAA running)
npm run test:integration

# Run baseline tests
npm run test:baseline

# Run all tests
npm test

# Generate report
npm run report
```

## Prerequisites

- Node.js >= 18
- `@opena2a/arp` (linked as file dependency from `../opena2a-arp`)
- [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) (for integration tests only)

## Test Categories

### Atomic Tests (25 tests)
Discrete, self-contained tests that exercise individual ARP capabilities. No external dependencies required — events are injected directly into the ARP engine.

| Group | Tests | Description |
|-------|-------|-------------|
| Process | AT-PROC-001 through 005 | Child process spawn, suspicious binaries, CPU, privilege escalation |
| Network | AT-NET-001 through 005 | Outbound connections, suspicious hosts, burst detection, host bypass |
| Filesystem | AT-FS-001 through 005 | Sensitive paths, credential files, mass creation, dotfile writes |
| Intelligence | AT-INT-001 through 005 | L0 rules, L1 anomaly scoring, L2 escalation, budget, baselines |
| Enforcement | AT-ENF-001 through 005 | Log, alert callback, SIGSTOP pause, SIGTERM kill, SIGCONT resume |

### Integration Tests (8 tests)
End-to-end scenarios that simulate multi-step attack chains. Uses DVAA agents as attack targets when available, falls back to event injection for CI.

| Test | Scenario | ATLAS |
|------|----------|-------|
| INT-001 | Data exfiltration chain | AML.T0057 |
| INT-002 | MCP tool abuse (path traversal + command injection) | AML.T0056 |
| INT-003 | Prompt injection with anomaly detection | AML.T0051 |
| INT-004 | A2A trust exploitation | AML.T0024 |
| INT-005 | Baseline learning then attack burst | AML.T0015 |
| INT-006 | Multi-monitor event correlation | AML.T0046 |
| INT-007 | Budget exhaustion then real attack | AML.T0029 |
| INT-008 | Kill switch and recovery | AML.TA0006 |

### Baseline Tests (3 tests)
Behavioral baseline validation — false positive rates and anomaly detection accuracy.

| Test | Scenario |
|------|----------|
| BL-001 | Normal agent profile (zero false positives) |
| BL-002 | Controlled anomaly injection |
| BL-003 | Baseline persistence across restarts |

## Architecture

```
┌─────────────────────────────────────────────┐
│                  Test Suite                   │
│  ┌──────────┐ ┌───────────┐ ┌────────────┐  │
│  │  Atomic  │ │Integration│ │  Baseline  │  │
│  │ 25 tests │ │  8 tests  │ │  3 tests   │  │
│  └────┬─────┘ └─────┬─────┘ └─────┬──────┘  │
│       │             │              │         │
│  ┌────┴─────────────┴──────────────┴──────┐  │
│  │            Test Harness                │  │
│  │  ArpWrapper | EventCollector | Metrics │  │
│  │  DVAAClient | DVAAManager | MockLLM    │  │
│  └────────────────┬───────────────────────┘  │
│                   │                          │
├───────────────────┼──────────────────────────┤
│                   ▼                          │
│  ┌────────────────────────────────────────┐  │
│  │     @opena2a/arp (System Under Test)   │  │
│  │  ProcessMonitor | NetworkMonitor       │  │
│  │  FilesystemMonitor | EventEngine       │  │
│  │  IntelligenceCoordinator | Enforcement │  │
│  └────────────────────────────────────────┘  │
│                   │                          │
│                   ▼                          │
│  ┌────────────────────────────────────────┐  │
│  │     DVAA (Optional Attack Targets)     │  │
│  │  10 agents | 3 protocols | 8 vulns     │  │
│  └────────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## MITRE ATLAS Coverage

| ATLAS Technique | Count | Category |
|----------------|-------|----------|
| AML.T0015 | 5 | Evasion/Detection |
| AML.T0018 | 1 | Persistence |
| AML.T0024 | 3 | Exfiltration |
| AML.T0029 | 5 | Denial of Service |
| AML.T0046 | 5 | Unsafe Inference |
| AML.T0051 | 1 | Prompt Injection |
| AML.T0054 | 2 | Jailbreak |
| AML.T0056 | 1 | Plugin Compromise |
| AML.T0057 | 5 | Data Leakage |
| AML.TA0006 | 7 | Attack Lifecycle |

See [docs/mitre-atlas-mapping.md](docs/mitre-atlas-mapping.md) for detailed test-to-technique mapping.

## OWASP Agentic Top 10 Coverage

| OWASP ID | Category | Tests |
|----------|----------|-------|
| A01 | Prompt Injection | 3 |
| A04 | Excessive Agency | 13 |
| A06 | Excessive Consumption | 5 |
| A07 | System Prompt Leakage | 6 |

See [docs/owasp-agentic-mapping.md](docs/owasp-agentic-mapping.md) for detailed mapping.

## Adding Tests

1. Create a new test file in the appropriate directory
2. Use the `ArpWrapper` from `src/harness/arp-wrapper` for setup
3. Inject events or enable monitors as needed
4. Add ATLAS/OWASP annotations in comments
5. Update the mapping docs

```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ArpWrapper } from '../../harness/arp-wrapper';

// AT-XXX-NNN: Description
// ATLAS: AML.TNNNN
// OWASP: ANN
describe('AT-XXX-NNN: Description', () => {
  let arp: ArpWrapper;

  beforeEach(async () => {
    arp = new ArpWrapper({ monitors: { process: false } });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
  });

  it('detects the expected behavior', async () => {
    await arp.injectEvent({
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'Test scenario',
      data: { /* scenario-specific data */ },
    });

    expect(arp.collector.hasEvent(e => e.category === 'violation')).toBe(true);
  });
});
```

## Known Gaps (Documented by Tests)

| # | Gap | Severity | Test |
|---|-----|----------|------|
| 6 | Anomaly baselines not persisted across restarts | Medium | BL-003 |
| 7 | No connection rate anomaly detection | Medium | AT-NET-003 |
| 8 | No HTTP response/output monitoring | Arch | INT-003 |
| 9 | No event correlation across monitors | Arch | INT-006 |

## License

Apache-2.0
