# OWASP Agentic Top 10 Test Mapping

ARP Lab maps tests to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) to demonstrate coverage of the most critical security risks in AI agent systems.

## Coverage by Category

### A01 — Prompt Injection
Manipulation of agent behavior through crafted inputs that override or bypass system instructions.

| Test ID | Scenario | Monitor |
|---------|----------|---------|
| AT-INT-001 | L0 rule classification detects threat patterns | Intelligence |
| AT-INT-003 | L2 LLM escalation defers enforcement for confirmation | Intelligence |
| INT-003 | Normal baseline → prompt injection → anomaly burst | Integration |

**ARP Detection:** L0 rules classify severity. L1 detects behavioral deviation from baseline. L2 can confirm via LLM analysis.

### A04 — Excessive Agency
Agent performs actions beyond its declared capabilities or authorized scope.

| Test ID | Scenario | Monitor |
|---------|----------|---------|
| AT-PROC-001 | Unauthorized child process spawning | Process |
| AT-PROC-002 | Suspicious binary execution (curl, wget, nc) | Process |
| AT-PROC-004 | Privilege escalation to root | Process |
| AT-FS-002 | File access outside allowed paths | Filesystem |
| AT-FS-005 | Shell config modification (.bashrc, .zshrc) | Filesystem |
| AT-NET-004 | Allowed host bypass via subdomain | Network |
| AT-INT-002 | Statistical anomaly in behavior pattern | Intelligence |
| AT-INT-005 | Baseline learning detects capability drift | Intelligence |
| INT-002 | MCP tool abuse (path traversal + command injection) | Integration |
| INT-004 | A2A trust exploitation via identity spoofing | Integration |
| INT-005 | Slow baseline poisoning then attack | Integration |
| INT-006 | Multi-monitor correlation of excessive actions | Integration |
| INT-008 | Kill switch response to excessive agency | Integration |

**ARP Detection:** Process monitor tracks all child processes and suspicious binaries. Filesystem monitor enforces path boundaries. Network monitor validates allowed hosts.

### A06 — Excessive Consumption
Agent consumes resources beyond reasonable bounds, causing denial of service.

| Test ID | Scenario | Monitor |
|---------|----------|---------|
| AT-PROC-003 | High CPU usage detection (>90%) | Process |
| AT-NET-003 | Connection burst (rapid outbound connections) | Network |
| AT-FS-004 | Mass file creation | Filesystem |
| AT-INT-004 | L2 budget exhaustion attack | Intelligence |
| INT-007 | Budget exhaustion then real attack | Integration |

**ARP Detection:** Process monitor tracks CPU/memory. Network monitor detects connection bursts. Budget controller prevents L2 cost overruns.

### A07 — System Prompt Leakage
Agent inadvertently exposes system prompts, credentials, or sensitive configuration.

| Test ID | Scenario | Monitor |
|---------|----------|---------|
| AT-NET-001 | New outbound connection to unknown host | Network |
| AT-NET-002 | Connection to suspicious host (webhook.site) | Network |
| AT-NET-005 | Exfiltration to known destinations | Network |
| AT-FS-001 | Sensitive path access (.ssh, .aws) | Filesystem |
| AT-FS-003 | Credential file access (.env, .npmrc, .pgpass) | Filesystem |
| INT-001 | End-to-end data exfiltration chain | Integration |

**ARP Detection:** Network monitor maintains suspicious host list. Filesystem monitor protects sensitive paths. Combined detection provides defense-in-depth.

## Coverage Summary

| OWASP ID | Category | Tests | Coverage Level |
|----------|----------|-------|---------------|
| A01 | Prompt Injection | 3 | Moderate — L0/L1/L2 detection |
| A04 | Excessive Agency | 13 | Strong — multi-monitor coverage |
| A06 | Excessive Consumption | 5 | Good — resource + budget tracking |
| A07 | System Prompt Leakage | 6 | Good — network + filesystem guards |
| **Total** | | **27 unique tests** | |

## Gaps and Future Coverage

| OWASP ID | Category | Gap |
|----------|----------|-----|
| A02 | Insecure Output Handling | No HTTP response monitoring (architectural gap #8) |
| A03 | Insecure Tool Use | Partial — covered via process/filesystem, no MCP-specific monitor |
| A05 | Insecure Memory | No conversation/context monitoring |
| A08 | Insecure Agents Interop | Partial — network monitoring only, no A2A protocol analysis |
| A09 | Overreliance | Out of scope for runtime monitoring |
| A10 | Misalignment | Requires behavioral alignment verification (future L2 capability) |
