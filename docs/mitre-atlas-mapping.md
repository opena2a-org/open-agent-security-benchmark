# MITRE ATLAS Test Mapping

ARP Lab maps every test to [MITRE ATLAS](https://atlas.mitre.org/) techniques for AI/ML systems. This provides a standardized framework for understanding what each test validates.

## Technique Coverage

### AML.T0015 — Evasion
Adversary attempts to evade detection by adapting behavior over time.

| Test ID | Description |
|---------|-------------|
| AT-INT-002 | L1 statistical anomaly scoring detects deviations from baseline |
| AT-INT-005 | Baseline learning and evasion detection via Z-score |
| INT-005 | Baseline learning then attack burst — slow poisoning evasion |
| BL-002 | Controlled anomaly injection into established baseline |
| BL-003 | Baseline persistence gap — attacker can reset detection by restarting |

### AML.T0018 — Persistence
Adversary maintains foothold via system configuration modification.

| Test ID | Description |
|---------|-------------|
| AT-FS-005 | Shell config dotfile write (.bashrc, .zshrc, .profile) detection |

### AML.T0024 — Exfiltration via ML Model
Data exfiltration through model channels or network connections.

| Test ID | Description |
|---------|-------------|
| AT-NET-001 | New outbound connection detection |
| AT-NET-004 | Allowed host bypass via subdomain matching |
| INT-004 | A2A trust exploitation for data exfiltration |

### AML.T0029 — Denial of Service
Resource exhaustion or service disruption targeting AI systems.

| Test ID | Description |
|---------|-------------|
| AT-PROC-003 | High CPU usage detection (>90%) |
| AT-NET-003 | Connection burst detection (rapid new connections) |
| AT-FS-004 | Mass file creation detection |
| AT-INT-004 | L2 budget exhaustion attack |
| INT-007 | Budget exhaustion then real attack bypass |

### AML.T0046 — Unsafe ML Inference
Exploitation of ML inference capabilities for unintended actions.

| Test ID | Description |
|---------|-------------|
| AT-PROC-001 | Child process spawn detection during inference |
| AT-PROC-002 | Suspicious binary execution (curl, wget, nc) |
| AT-PROC-004 | Privilege escalation to root |
| AT-FS-002 | File access outside allowed paths |
| INT-006 | Multi-monitor correlation from single attack |

### AML.T0051 — LLM Prompt Injection
Manipulation of LLM behavior through crafted inputs.

| Test ID | Description |
|---------|-------------|
| INT-003 | Prompt injection with anomaly detection response |

### AML.T0054 — LLM Jailbreak
Bypassing LLM safety constraints and guardrails.

| Test ID | Description |
|---------|-------------|
| AT-INT-001 | L0 rule-based threat classification |
| AT-INT-003 | L2 LLM escalation for jailbreak confirmation |

### AML.T0056 — LLM Plugin Compromise
Exploitation of LLM tool/plugin interfaces.

| Test ID | Description |
|---------|-------------|
| INT-002 | MCP tool abuse — path traversal + command injection |

### AML.T0057 — Data Leakage
Unauthorized disclosure of sensitive data through AI systems.

| Test ID | Description |
|---------|-------------|
| AT-NET-002 | Connection to known-bad host (webhook.site, pastebin) |
| AT-NET-005 | Exfiltration destination detection (transfer.sh, requestbin) |
| AT-FS-001 | Sensitive path access (.ssh, .aws, .gnupg) |
| AT-FS-003 | Credential file access (.npmrc, .env, .netrc) |
| INT-001 | End-to-end data exfiltration chain |

### AML.TA0006 — ML Attack Lifecycle
Defensive response and recovery actions.

| Test ID | Description |
|---------|-------------|
| AT-PROC-005 | Process termination tracking |
| AT-ENF-001 | Log enforcement action |
| AT-ENF-002 | Alert callback execution |
| AT-ENF-003 | Process pause via SIGSTOP |
| AT-ENF-004 | Process kill via SIGTERM |
| AT-ENF-005 | Process resume via SIGCONT |
| INT-008 | Kill switch and recovery |

## Coverage Summary

| ATLAS Technique | Tests | Category |
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
| **Total** | **35 tests** | **10 techniques** |
