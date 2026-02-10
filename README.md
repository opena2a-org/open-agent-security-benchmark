# ARP Lab — Security Testing for Agent Runtime Protection

Comprehensive test suite that validates [ARP](https://github.com/opena2a-org/arp)'s detection capabilities against realistic attack scenarios. 182 tests across 42 files, mapped to MITRE ATLAS and OWASP Agentic Top 10.

## Test Results

| Category | Files | Tests | Status |
|----------|-------|-------|--------|
| Atomic (unit-level) | 25 | 103 | All passing |
| Integration | 8 | 33 | All passing |
| Baseline | 3 | 13 | All passing |
| E2E — Live Monitors | 3 | 9 | All passing |
| E2E — Interceptors | 3 | 14 | All passing |
| **Total** | **42** | **182** | **100% pass rate** |

## Setup

Requires [ARP](https://github.com/opena2a-org/arp) cloned as a sibling directory.

```bash
git clone https://github.com/opena2a-org/arp.git
git clone https://github.com/opena2a-org/arp-lab.git

cd arp && npm install && npm run build && cd ..
cd arp-lab && npm install
```

## Running Tests

```bash
npm test                    # All 182 tests
npm run test:atomic         # 25 atomic tests (no external deps)
npm run test:integration    # 8 integration tests
npm run test:baseline       # 3 baseline tests
npx vitest run src/e2e/     # 6 E2E tests (real OS detection)
```

## Test Categories

### Atomic Tests (`src/atomic/`)

Discrete unit tests that exercise individual ARP capabilities via direct event injection. No external dependencies.

**Process Detection** — 5 files

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-PROC-001 | AML.T0046 | Child process spawn detection |
| AT-PROC-002 | AML.T0046 | Suspicious binary detection (curl, wget, nc) |
| AT-PROC-003 | AML.T0029 | High CPU anomaly detection |
| AT-PROC-004 | AML.T0046 | Privilege escalation (root user) |
| AT-PROC-005 | AML.TA0006 | Process termination tracking |

**Network Detection** — 5 files

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-NET-001 | AML.T0024 | New outbound connection detection |
| AT-NET-002 | AML.T0057 | Suspicious host flagging (webhook.site, ngrok) |
| AT-NET-003 | AML.T0029 | Connection burst detection |
| AT-NET-004 | AML.T0024 | Subdomain bypass prevention |
| AT-NET-005 | AML.T0057 | Exfiltration destination detection |

**Filesystem Detection** — 5 files

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-FS-001 | AML.T0057 | Sensitive path access (.ssh, .aws, .gnupg) |
| AT-FS-002 | AML.T0046 | Outside-allowed-paths detection |
| AT-FS-003 | AML.T0057 | Credential file access (.npmrc, .pypirc, .netrc) |
| AT-FS-004 | AML.T0029 | Mass file creation DoS |
| AT-FS-005 | AML.T0018 | Shell config persistence (.bashrc, .zshrc) |

**Intelligence** — 5 files

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-INT-001 | AML.T0054 | L0 rule matching and enforcement triggers |
| AT-INT-002 | AML.T0015 | L1 z-score anomaly scoring |
| AT-INT-003 | AML.T0054 | L2 LLM confirmation deferral |
| AT-INT-004 | AML.T0029 | Budget exhaustion handling |
| AT-INT-005 | AML.T0015 | Baseline learning and reset |

**Enforcement** — 5 files

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-ENF-001 | AML.TA0006 | Log action execution |
| AT-ENF-002 | AML.TA0006 | Alert callback invocation |
| AT-ENF-003 | AML.TA0006 | SIGSTOP pause |
| AT-ENF-004 | AML.TA0006 | SIGTERM/SIGKILL |
| AT-ENF-005 | AML.TA0006 | SIGCONT resume |

### Integration Tests (`src/integration/`)

Multi-step attack scenarios using event injection. Optionally validates against live [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) agents.

| Test | ATLAS | Scenario |
|------|-------|----------|
| INT-001 | AML.T0057 | Data exfiltration chain (internal contact → webhook.site) |
| INT-002 | AML.T0056 | MCP tool abuse (path traversal + command injection) |
| INT-003 | AML.T0051 | Prompt injection with anomaly detection |
| INT-004 | AML.T0024 | A2A trust exploitation (spoofed agent identity) |
| INT-005 | AML.T0015 | Baseline learning → attack burst detection |
| INT-006 | AML.T0046 | Multi-monitor correlation (process + network + filesystem) |
| INT-007 | AML.T0029 | Budget exhaustion via noise flood |
| INT-008 | AML.TA0006 | Kill switch → process death → recovery |

### Baseline Tests (`src/baseline/`)

| Test | What It Proves |
|------|----------------|
| BL-001 | Zero false positives from normal agent activity |
| BL-002 | Controlled anomaly injection triggers detection |
| BL-003 | Baseline persistence gap (documented limitation) |

### E2E Tests (`src/e2e/`)

Real OS-level detection — no mocks, no event injection.

**Live Monitors** (OS-level polling):

| Test | Latency | What It Proves |
|------|---------|----------------|
| E2E-001 | ~200ms | fs.watch detects .env, .ssh, .bashrc, .npmrc writes |
| E2E-002 | ~1000ms | ps polling detects child processes, suspicious binaries |
| E2E-003 | ~1000ms | lsof detects outbound TCP (skips if unavailable) |

**Interceptors** (application-level hooks):

| Test | Latency | What It Proves |
|------|---------|----------------|
| E2E-004 | <1ms | child_process.spawn/exec intercepted before execution |
| E2E-005 | <1ms | net.Socket.connect intercepted before connection |
| E2E-006 | <1ms | fs.writeFileSync/readFileSync intercepted before I/O |

## Test Harness

| File | Purpose |
|------|---------|
| `arp-wrapper.ts` | Wraps ARP with temp dataDir, event collection, injection helpers |
| `event-collector.ts` | Captures events with async `waitForEvent(predicate, timeout)` |
| `mock-llm-adapter.ts` | Deterministic LLM for L2 testing (pattern-based responses) |
| `dvaa-client.ts` | HTTP client for DVAA agent endpoints |
| `dvaa-manager.ts` | DVAA process lifecycle (spawn, health check, teardown) |
| `metrics.ts` | Detection rate, false positive rate, P95 latency computation |

## MITRE ATLAS Coverage

10 unique techniques across 42 test files:

| Technique | ID | Tests |
|-----------|----|-------|
| Unsafe ML Inference | AML.T0046 | AT-PROC-001/002/004, AT-FS-002, INT-006, E2E-002/004 |
| Data Leakage | AML.T0057 | AT-NET-002/005, AT-FS-001/003, INT-001, E2E-001/006 |
| Exfiltration | AML.T0024 | AT-NET-001/004, INT-004, E2E-003/005 |
| Persistence | AML.T0018 | AT-FS-005, E2E-001/006 |
| Denial of Service | AML.T0029 | AT-PROC-003, AT-NET-003, AT-INT-004, INT-007 |
| Evasion | AML.T0015 | AT-INT-002/005, INT-005, BL-002/003 |
| Jailbreak | AML.T0054 | AT-INT-001/003 |
| MCP Compromise | AML.T0056 | INT-002 |
| Prompt Injection | AML.T0051 | INT-003 |
| Defense Response | AML.TA0006 | AT-ENF-001-005, AT-PROC-005, INT-008 |

## Known Gaps (Documented by Tests)

| Gap | Severity | Test |
|-----|----------|------|
| Anomaly baselines not persisted across restarts | Medium | BL-003 |
| No connection rate anomaly detection | Medium | AT-NET-003 |
| No HTTP response/output monitoring | Architectural | INT-003 |
| No cross-monitor event correlation | Architectural | INT-006 |

## License

Apache-2.0
