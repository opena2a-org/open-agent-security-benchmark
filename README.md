# OASB — Open Agent Security Benchmark

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-182%20passing-brightgreen)](https://github.com/opena2a-org/oasb)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE%20ATLAS-10%20techniques-teal)](https://atlas.mitre.org/)

**Can your security product actually detect attacks against AI agents?**

182 standardized attack scenarios across 42 test files, mapped to MITRE ATLAS and OWASP Agentic Top 10. Run OASB against any agent runtime security product to measure detection coverage.

[OASB Website](https://oasb.ai) | [OpenA2A](https://opena2a.org) | [MITRE ATLAS Coverage](#mitre-atlas-coverage) | [ARP (Reference Adapter)](https://github.com/opena2a-org/arp)

---

## Table of Contents

- [Quick Start](#quick-start)
- [What Gets Tested](#what-gets-tested)
- [Test Categories](#test-categories)
  - [Atomic Tests](#atomic-tests-srcatomic) — 25 discrete detection tests
  - [Integration Tests](#integration-tests-srcintegration) — 8 multi-step attack chains
  - [Baseline Tests](#baseline-tests-srcbaseline) — 3 false positive validations
  - [E2E Tests](#e2e-tests-srce2e) — 6 real OS-level detection tests
- [MITRE ATLAS Coverage](#mitre-atlas-coverage)
- [Test Harness](#test-harness)
- [Known Detection Gaps](#known-detection-gaps)
- [License](#license)

---

## Quick Start

Currently ships with [ARP](https://github.com/opena2a-org/arp) as the reference adapter. Vendor adapter interface coming soon.

```bash
git clone https://github.com/opena2a-org/arp.git
git clone https://github.com/opena2a-org/oasb.git

cd arp && npm install && npm run build && cd ..
cd oasb && npm install
```

### Run the Benchmark

```bash
npm test                    # Full benchmark (182 tests)
npm run test:atomic         # 25 atomic tests (no external deps)
npm run test:integration    # 8 integration scenarios
npm run test:baseline       # 3 baseline tests
npx vitest run src/e2e/     # 6 E2E tests (real OS detection)
```

---

## What Gets Tested

| Category | Tests | What It Evaluates |
|----------|-------|-------------------|
| Process detection | 25 | Child process spawns, suspicious binaries, privilege escalation, CPU anomalies |
| Network detection | 20 | Outbound connections, suspicious hosts, exfiltration, subdomain bypass |
| Filesystem detection | 28 | Sensitive path access, credential files, dotfile persistence, mass file DoS |
| Intelligence layers | 21 | Rule matching, anomaly scoring, LLM escalation, budget exhaustion |
| Enforcement actions | 18 | Logging, alerting, process pause (SIGSTOP), kill (SIGTERM/SIGKILL), resume |
| Multi-step attacks | 33 | Data exfiltration chains, MCP tool abuse, prompt injection, A2A trust exploitation |
| Baseline behavior | 13 | False positive rates, anomaly injection, baseline persistence |
| Real OS detection | 14 | Live filesystem watches, process polling, network monitoring |
| Application-level hooks | 14 | Pre-execution interception of spawn, connect, read/write |
| **Total** | **182** | **10 MITRE ATLAS techniques** |

---

## Test Categories

### Atomic Tests (`src/atomic/`)

Discrete tests that exercise individual detection capabilities via direct event injection. No external dependencies required.

<details>
<summary><strong>Process Detection</strong> — 5 files</summary>

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-PROC-001 | AML.T0046 | Child process spawn detection |
| AT-PROC-002 | AML.T0046 | Suspicious binary detection (curl, wget, nc) |
| AT-PROC-003 | AML.T0029 | High CPU anomaly detection |
| AT-PROC-004 | AML.T0046 | Privilege escalation (root user) |
| AT-PROC-005 | AML.TA0006 | Process termination tracking |

</details>

<details>
<summary><strong>Network Detection</strong> — 5 files</summary>

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-NET-001 | AML.T0024 | New outbound connection detection |
| AT-NET-002 | AML.T0057 | Suspicious host flagging (webhook.site, ngrok) |
| AT-NET-003 | AML.T0029 | Connection burst detection |
| AT-NET-004 | AML.T0024 | Subdomain bypass prevention |
| AT-NET-005 | AML.T0057 | Exfiltration destination detection |

</details>

<details>
<summary><strong>Filesystem Detection</strong> — 5 files</summary>

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-FS-001 | AML.T0057 | Sensitive path access (.ssh, .aws, .gnupg) |
| AT-FS-002 | AML.T0046 | Outside-allowed-paths detection |
| AT-FS-003 | AML.T0057 | Credential file access (.npmrc, .pypirc, .netrc) |
| AT-FS-004 | AML.T0029 | Mass file creation DoS |
| AT-FS-005 | AML.T0018 | Shell config persistence (.bashrc, .zshrc) |

</details>

<details>
<summary><strong>Intelligence</strong> — 5 files</summary>

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-INT-001 | AML.T0054 | Rule-based classification and enforcement |
| AT-INT-002 | AML.T0015 | Statistical anomaly scoring (z-score) |
| AT-INT-003 | AML.T0054 | LLM-assisted assessment escalation |
| AT-INT-004 | AML.T0029 | Budget exhaustion handling |
| AT-INT-005 | AML.T0015 | Baseline learning and reset |

</details>

<details>
<summary><strong>Enforcement</strong> — 5 files</summary>

| Test | ATLAS | What It Proves |
|------|-------|----------------|
| AT-ENF-001 | AML.TA0006 | Log action execution |
| AT-ENF-002 | AML.TA0006 | Alert callback invocation |
| AT-ENF-003 | AML.TA0006 | SIGSTOP pause |
| AT-ENF-004 | AML.TA0006 | SIGTERM/SIGKILL |
| AT-ENF-005 | AML.TA0006 | SIGCONT resume |

</details>

---

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

---

### Baseline Tests (`src/baseline/`)

| Test | What It Proves |
|------|----------------|
| BL-001 | Zero false positives from normal agent activity |
| BL-002 | Controlled anomaly injection triggers detection |
| BL-003 | Baseline persistence across restarts |

---

### E2E Tests (`src/e2e/`)

Real OS-level detection — no mocks, no event injection.

<details>
<summary><strong>Live Monitors</strong> — OS-level polling</summary>

| Test | Latency | What It Proves |
|------|---------|----------------|
| E2E-001 | ~200ms | fs.watch detects .env, .ssh, .bashrc, .npmrc writes |
| E2E-002 | ~1000ms | ps polling detects child processes, suspicious binaries |
| E2E-003 | ~1000ms | lsof detects outbound TCP (skips if unavailable) |

</details>

<details>
<summary><strong>Interceptors</strong> — application-level hooks</summary>

| Test | Latency | What It Proves |
|------|---------|----------------|
| E2E-004 | <1ms | child_process.spawn/exec intercepted before execution |
| E2E-005 | <1ms | net.Socket.connect intercepted before connection |
| E2E-006 | <1ms | fs.writeFileSync/readFileSync intercepted before I/O |

</details>

---

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

---

## Test Harness

| File | Purpose |
|------|---------|
| `arp-wrapper.ts` | Reference adapter — wraps ARP with temp dataDir, event collection, injection helpers |
| `event-collector.ts` | Captures events with async `waitForEvent(predicate, timeout)` |
| `mock-llm-adapter.ts` | Deterministic LLM for intelligence layer testing (pattern-based responses) |
| `dvaa-client.ts` | HTTP client for DVAA agent endpoints |
| `dvaa-manager.ts` | DVAA process lifecycle (spawn, health check, teardown) |
| `metrics.ts` | Detection rate, false positive rate, P95 latency computation |

---

## Known Detection Gaps

Tests document gaps so vendors can track what their product does and doesn't catch.

| Gap | Severity | Test |
|-----|----------|------|
| Anomaly baselines not persisted across restarts | Medium | BL-003 |
| No connection rate anomaly detection | Medium | AT-NET-003 |
| No HTTP response/output monitoring | Architectural | INT-003 |
| No cross-monitor event correlation | Architectural | INT-006 |

---

## License

Apache-2.0

---

## OpenA2A Ecosystem

| Project | What it does |
|---------|-------------|
| [**OASB**](https://github.com/opena2a-org/oasb) | Open Agent Security Benchmark — 182 attack scenarios |
| [**ARP**](https://github.com/opena2a-org/arp) | Runtime security monitoring for AI agents |
| [**HackMyAgent**](https://github.com/opena2a-org/hackmyagent) | Security scanner — 147 checks, attack mode, auto-fix |
| [**AIM**](https://github.com/opena2a-org/agent-identity-management) | Identity and access management for AI agents |
| [**Secretless AI**](https://github.com/opena2a-org/secretless-ai) | Keep credentials out of AI context windows |
| [**DVAA**](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Deliberately vulnerable AI agents for security training |

[Website](https://opena2a.org) · [OASB](https://oasb.ai) · [Discord](https://discord.gg/uRZa3KXgEn) · [Email](mailto:info@opena2a.org)
