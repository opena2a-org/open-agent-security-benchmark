# ARP Lab Test Report

Generated: 2026-02-10

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | 182 |
| Passed | 182 |
| Failed | 0 |
| Skipped | 0 |
| Pass Rate | 100.0% |
| Test Files | 42 |

### Test Breakdown

| Category | Files | Tests |
|----------|-------|-------|
| Atomic (unit-level) | 25 | 103 |
| Integration | 8 | 33 |
| Baseline | 3 | 13 |
| E2E — Live Monitors | 3 | 9 |
| E2E — Interceptors | 3 | 14 |
| **Total** | **42** | **182** |

## Architecture: Two Detection Layers

ARP uses two complementary detection approaches:

### Layer 1: OS-Level Monitors (polling)
- **ProcessMonitor**: Polls `ps -ax -o pid=,ppid=` to build process tree, detect new children, suspicious binaries, termination
- **NetworkMonitor**: Polls `lsof -i` (macOS) / `ss` (Linux) for ESTABLISHED TCP connections
- **FilesystemMonitor**: Uses `fs.watch()` with recursive flag on watched directories

### Layer 2: Application-Level Interceptors (zero-latency)
- **ProcessInterceptor**: Hooks `child_process.spawn/exec/execFile/fork` — catches every process spawn BEFORE execution
- **NetworkInterceptor**: Hooks `net.Socket.prototype.connect` — catches every TCP connection BEFORE it's made
- **FilesystemInterceptor**: Hooks `fs.readFile/writeFile/mkdir/unlink` — catches every file I/O BEFORE it happens

Interceptors provide zero-latency, 100% accurate detection with no kernel dependency — better than eBPF for Node.js agents because they intercept at the application level with full semantic context.

## MITRE ATLAS Coverage

| Test ID | ATLAS Technique | Description | Status |
|---------|----------------|-------------|--------|
| AT-PROC-001 | AML.T0046 | Unsafe inference spawns child process | PASS |
| AT-PROC-002 | AML.T0046 | Suspicious binary execution (curl/wget) | PASS |
| AT-PROC-003 | AML.T0029 | Denial of service via CPU exhaustion | PASS |
| AT-PROC-004 | AML.T0046 | Privilege escalation via root process | PASS |
| AT-PROC-005 | AML.TA0006 | Process termination in attack lifecycle | PASS |
| AT-NET-001 | AML.T0024 | Exfiltration via new outbound connection | PASS |
| AT-NET-002 | AML.T0057 | Data leakage to known-bad host | PASS |
| AT-NET-003 | AML.T0029 | Connection burst denial of service | PASS |
| AT-NET-004 | AML.T0024 | Allowed host bypass via subdomain | PASS |
| AT-NET-005 | AML.T0057 | Exfiltration to known destinations | PASS |
| AT-FS-001 | AML.T0057 | Sensitive credential file access | PASS |
| AT-FS-002 | AML.T0046 | File access outside allowed paths | PASS |
| AT-FS-003 | AML.T0057 | Credential file access detection | PASS |
| AT-FS-004 | AML.T0029 | Mass file creation DoS | PASS |
| AT-FS-005 | AML.T0018 | Persistence via shell config modification | PASS |
| AT-INT-001 | AML.T0054 | L0 rule-based threat classification | PASS |
| AT-INT-002 | AML.T0015 | L1 statistical anomaly scoring | PASS |
| AT-INT-003 | AML.T0054 | L2 LLM escalation deferral | PASS |
| AT-INT-004 | AML.T0029 | Budget exhaustion denial of service | PASS |
| AT-INT-005 | AML.T0015 | Baseline learning and evasion detection | PASS |
| AT-ENF-001 | AML.TA0006 | Log enforcement action | PASS |
| AT-ENF-002 | AML.TA0006 | Alert callback execution | PASS |
| AT-ENF-003 | AML.TA0006 | Process pause via SIGSTOP | PASS |
| AT-ENF-004 | AML.TA0006 | Process kill via SIGTERM | PASS |
| AT-ENF-005 | AML.TA0006 | Process resume via SIGCONT | PASS |
| E2E-001 | AML.T0057, AML.T0018 | Live filesystem detection (fs.watch) | PASS |
| E2E-002 | AML.T0046 | Live process detection (ps polling) | PASS |
| E2E-003 | AML.T0024 | Live network detection (lsof/ss) | PASS |
| E2E-004 | AML.T0046 | Process interceptor (child_process hooks) | PASS |
| E2E-005 | AML.T0024 | Network interceptor (net.Socket hooks) | PASS |
| E2E-006 | AML.T0057, AML.T0018 | Filesystem interceptor (fs module hooks) | PASS |
| INT-001 | AML.T0057 | End-to-end data exfiltration chain | PASS |
| INT-002 | AML.T0056 | MCP plugin compromise chain | PASS |
| INT-003 | AML.T0051 | Prompt injection with anomaly detection | PASS |
| INT-004 | AML.T0024 | A2A trust exploitation | PASS |
| INT-005 | AML.T0015 | Evasion via slow baseline poisoning | PASS |
| INT-006 | AML.T0046 | Multi-monitor event correlation | PASS |
| INT-007 | AML.T0029 | Budget exhaustion denial of service | PASS |
| INT-008 | AML.TA0006 | Kill switch defensive response | PASS |
| BL-001 | N/A | Normal agent profile (false positive check) | PASS |
| BL-002 | AML.T0015 | Controlled anomaly injection | PASS |
| BL-003 | AML.T0015 | Baseline persistence gap documentation | PASS |

**Unique ATLAS techniques covered:** 10

## OWASP Agentic Top 10 Coverage

| OWASP ID | Category | Tests |
|----------|----------|-------|
| A01 | Prompt Injection | INT-003, AT-INT-003 |
| A04 | Excessive Agency | AT-PROC-001/002, E2E-002/004, INT-002 |
| A06 | Excessive Consumption | AT-INT-004, INT-007 |
| A07 | System Prompt Leakage | AT-FS-001/003, E2E-001/006 |

## E2E Test Details

### Live Monitor Tests (OS-level polling)

| Test | What It Proves | Detection Latency |
|------|---------------|-------------------|
| E2E-001 | fs.watch detects .env, .ssh, .bashrc, .npmrc writes | ~200ms |
| E2E-002 | ps polling detects child processes, suspicious binaries | ~1000ms |
| E2E-003 | lsof detects outbound TCP connections | ~1000ms (skips if lsof unavailable) |

### Interceptor Tests (application-level hooks)

| Test | What It Proves | Detection Latency |
|------|---------------|-------------------|
| E2E-004 | child_process.spawn/exec intercepted before execution | <1ms |
| E2E-005 | net.Socket.connect intercepted before connection | <1ms |
| E2E-006 | fs.writeFileSync/readFileSync intercepted before I/O | <1ms |

## Known Gaps (Documented)

| # | Gap | Severity | Test Coverage |
|---|-----|----------|--------------|
| 6 | Anomaly baselines not persisted across restarts | Medium | BL-003 |
| 7 | No connection rate anomaly detection | Medium | AT-NET-003 |
| 8 | No HTTP response/output monitoring | Arch | INT-003 |
| 9 | No event correlation across monitors | Arch | INT-006 |
