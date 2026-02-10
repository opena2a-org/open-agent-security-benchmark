> **[OpenA2A](https://opena2a.org)**: [AIM](https://opena2a.org/docs) · [HackMyAgent](https://hackmyagent.com) · [OASB](https://oasb.ai) · [ARP](https://github.com/opena2a-org/arp) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

# OASB — Open Agent Security Benchmark

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-182%20passing-brightgreen)](https://github.com/opena2a-org/oasb)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE%20ATLAS-10%20techniques-teal)](https://atlas.mitre.org/)

**MITRE ATT&CK Evaluations, but for AI agent security products.**

182 standardized attack scenarios that evaluate whether a runtime security product can detect and respond to threats against AI agents. Each test is mapped to MITRE ATLAS and OWASP Agentic Top 10. Plug in your product, run the suite, get a detection coverage scorecard.

[OASB Website](https://oasb.ai) | [OpenA2A](https://opena2a.org) | [MITRE ATLAS Coverage](#mitre-atlas-coverage) | [ARP (Reference Adapter)](https://github.com/opena2a-org/arp)

---

## What OASB Is (and Isn't)

OASB evaluates **security products**, not agents. It answers: "does your runtime protection actually catch these attacks?"

| | OASB | [HackMyAgent](https://github.com/opena2a-org/hackmyagent) |
|---|---|---|
| **Purpose** | Evaluate security *products* | Pentest AI *agents* |
| **Tests** | "Does your EDR catch this exfiltration?" | "Is your agent leaking credentials?" |
| **Audience** | Security product vendors, evaluators | Agent developers, red teams |
| **Analogous to** | [MITRE ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/) | [OWASP ZAP](https://www.zaproxy.org/) / Burp Suite |
| **Method** | Controlled lab — inject attacks, measure detection | Active scanning + adversarial payloads against live targets |
| **Output** | Detection coverage scorecard | Vulnerability report + auto-fix |

Use both together: **HackMyAgent** finds vulnerabilities in your agent, **OASB** proves your security product catches real attacks.

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

Currently ships with [ARP](https://github.com/opena2a-org/arp) as the reference adapter. Vendor adapter interface coming soon — implement the adapter for your product and run the same 182 tests.

```bash
git clone https://github.com/opena2a-org/arp.git
git clone https://github.com/opena2a-org/oasb.git

cd arp && npm install && npm run build && cd ..
cd oasb && npm install
```

### Run the Evaluation

```bash
npm test                    # Full evaluation (182 tests)
npm run test:atomic         # 25 atomic tests (no external deps)
npm run test:integration    # 8 integration scenarios
npm run test:baseline       # 3 baseline tests
npx vitest run src/e2e/     # 6 E2E tests (real OS detection)
```

---

## What Gets Tested

Each test simulates a specific attack technique and checks whether the security product under evaluation detects it, classifies it correctly, and responds appropriately.

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

Discrete tests that exercise individual detection capabilities. Each test injects a single attack event and verifies the product detects it with the correct classification and severity.

<details>
<summary><strong>Process Detection</strong> — 5 files</summary>

| Test | ATLAS | What the Product Should Detect |
|------|-------|-------------------------------|
| AT-PROC-001 | AML.T0046 | Child process spawn |
| AT-PROC-002 | AML.T0046 | Suspicious binary execution (curl, wget, nc) |
| AT-PROC-003 | AML.T0029 | High CPU anomaly |
| AT-PROC-004 | AML.T0046 | Privilege escalation (root user) |
| AT-PROC-005 | AML.TA0006 | Process termination |

</details>

<details>
<summary><strong>Network Detection</strong> — 5 files</summary>

| Test | ATLAS | What the Product Should Detect |
|------|-------|-------------------------------|
| AT-NET-001 | AML.T0024 | New outbound connection |
| AT-NET-002 | AML.T0057 | Connection to suspicious host (webhook.site, ngrok) |
| AT-NET-003 | AML.T0029 | Connection burst |
| AT-NET-004 | AML.T0024 | Subdomain bypass of allowlist |
| AT-NET-005 | AML.T0057 | Exfiltration destination |

</details>

<details>
<summary><strong>Filesystem Detection</strong> — 5 files</summary>

| Test | ATLAS | What the Product Should Detect |
|------|-------|-------------------------------|
| AT-FS-001 | AML.T0057 | Sensitive path access (.ssh, .aws, .gnupg) |
| AT-FS-002 | AML.T0046 | Access outside allowed paths |
| AT-FS-003 | AML.T0057 | Credential file access (.npmrc, .pypirc, .netrc) |
| AT-FS-004 | AML.T0029 | Mass file creation (DoS) |
| AT-FS-005 | AML.T0018 | Shell config modification (.bashrc, .zshrc) |

</details>

<details>
<summary><strong>Intelligence</strong> — 5 files</summary>

| Test | ATLAS | What the Product Should Do |
|------|-------|---------------------------|
| AT-INT-001 | AML.T0054 | Match rules and trigger enforcement |
| AT-INT-002 | AML.T0015 | Score statistical anomalies (z-score) |
| AT-INT-003 | AML.T0054 | Escalate to LLM-assisted assessment |
| AT-INT-004 | AML.T0029 | Handle budget exhaustion gracefully |
| AT-INT-005 | AML.T0015 | Learn and reset behavioral baselines |

</details>

<details>
<summary><strong>Enforcement</strong> — 5 files</summary>

| Test | ATLAS | What the Product Should Do |
|------|-------|---------------------------|
| AT-ENF-001 | AML.TA0006 | Execute log action |
| AT-ENF-002 | AML.TA0006 | Fire alert callback |
| AT-ENF-003 | AML.TA0006 | Pause process (SIGSTOP) |
| AT-ENF-004 | AML.TA0006 | Kill process (SIGTERM/SIGKILL) |
| AT-ENF-005 | AML.TA0006 | Resume paused process (SIGCONT) |

</details>

---

### Integration Tests (`src/integration/`)

Multi-step attack chains that combine multiple techniques. Tests whether the product can detect coordinated attacks, not just isolated events. Optionally validates against live [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) agents.

| Test | ATLAS | Attack Chain |
|------|-------|-------------|
| INT-001 | AML.T0057 | Data exfiltration: internal contact lookup → credential harvest → webhook.site POST |
| INT-002 | AML.T0056 | MCP tool abuse: path traversal + command injection via tool arguments |
| INT-003 | AML.T0051 | Prompt injection: establish baseline → inject malicious prompt → measure detection |
| INT-004 | AML.T0024 | A2A trust exploitation: spoofed agent identity → unauthorized data access |
| INT-005 | AML.T0015 | Evasion: 5 minutes normal traffic → sudden attack burst → verify anomaly detection |
| INT-006 | AML.T0046 | Multi-monitor correlation: single attack triggers process + network + filesystem events |
| INT-007 | AML.T0029 | Budget exhaustion: noise flood drains LLM budget → real attack goes unanalyzed |
| INT-008 | AML.TA0006 | Kill switch: critical threat → product kills agent → verify death → recovery |

---

### Baseline Tests (`src/baseline/`)

Every security product must avoid false positives. These tests verify the product stays quiet during normal operations.

| Test | What It Proves |
|------|----------------|
| BL-001 | Zero false positives from normal agent activity |
| BL-002 | Controlled anomaly injection triggers detection (not silent) |
| BL-003 | Baseline persistence across product restarts |

---

### E2E Tests (`src/e2e/`)

Real OS-level detection — no mocks, no event injection. These tests spawn real processes, open real connections, and write real files, then verify the product detects them.

<details>
<summary><strong>Live Monitors</strong> — OS-level polling</summary>

| Test | Latency | What the Product Should Detect |
|------|---------|-------------------------------|
| E2E-001 | ~200ms | fs.watch detects .env, .ssh, .bashrc, .npmrc writes |
| E2E-002 | ~1000ms | ps polling detects child processes, suspicious binaries |
| E2E-003 | ~1000ms | lsof detects outbound TCP (skips if unavailable) |

</details>

<details>
<summary><strong>Interceptors</strong> — application-level hooks</summary>

| Test | Latency | What the Product Should Intercept |
|------|---------|----------------------------------|
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

The harness wraps a security product via an adapter interface and provides event collection, injection, and metrics.

| File | Purpose |
|------|---------|
| `arp-wrapper.ts` | Reference adapter — wraps ARP with temp dataDir, event collection, injection helpers |
| `event-collector.ts` | Captures events with async `waitForEvent(predicate, timeout)` |
| `mock-llm-adapter.ts` | Deterministic LLM for intelligence layer testing (pattern-based responses) |
| `dvaa-client.ts` | HTTP client for DVAA vulnerable agent endpoints |
| `dvaa-manager.ts` | DVAA process lifecycle (spawn, health check, teardown) |
| `metrics.ts` | Detection rate, false positive rate, P95 latency computation |

To evaluate your own product: implement an adapter that translates OASB events into your product's API, then run the full suite. Vendor adapter interface spec coming soon.

---

## Known Detection Gaps

OASB documents what the reference product (ARP) does and doesn't catch. Other products may have different gap profiles — that's the point of running the benchmark.

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

| Project | Description | Install |
|---------|-------------|---------|
| [**AIM**](https://github.com/opena2a-org/agent-identity-management) | Agent Identity Management -- identity and access control for AI agents | `pip install aim-sdk` |
| [**HackMyAgent**](https://github.com/opena2a-org/hackmyagent) | Security scanner -- 147 checks, attack mode, auto-fix | `npx hackmyagent secure` |
| [**OASB**](https://github.com/opena2a-org/oasb) | Open Agent Security Benchmark -- 182 attack scenarios | `npm install @opena2a/oasb` |
| [**ARP**](https://github.com/opena2a-org/arp) | Agent Runtime Protection -- process, network, filesystem monitoring | `npm install @opena2a/arp` |
| [**Secretless AI**](https://github.com/opena2a-org/secretless-ai) | Keep credentials out of AI context windows | `npx secretless-ai init` |
| [**DVAA**](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Damn Vulnerable AI Agent -- security training and red-teaming | `docker pull opena2a/dvaa` |
