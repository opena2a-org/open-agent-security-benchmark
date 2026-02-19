// AT-AI-003: MCP Tool Call Scanning
// ATLAS: AML.T0056 (MCP Compromise)
// OWASP: A02 (Insecure Tool Use)
//
// Verifies that MCPProtocolInterceptor.scanToolCall() detects path traversal,
// command injection, and SSRF in MCP tool call parameters.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { EventEngine, MCPProtocolInterceptor, type ARPEvent } from '@opena2a/arp';

describe('AT-AI-003: MCP Tool Call Scanning', () => {
  let engine: EventEngine;
  let interceptor: MCPProtocolInterceptor;
  let events: ARPEvent[];

  beforeAll(async () => {
    engine = new EventEngine({ agentName: 'oasb-mcp-test' });
    interceptor = new MCPProtocolInterceptor(engine);
    events = [];
    engine.onEvent((event) => {
      if (event.category === 'threat' || event.category === 'violation') {
        events.push(event);
      }
    });
    await interceptor.start();
  });

  afterAll(async () => {
    await interceptor.stop();
  });

  function clearEvents(): void {
    events.length = 0;
  }

  // --- Path Traversal ---

  it('should detect path traversal in file read (MCP-001)', () => {
    clearEvents();
    const result = interceptor.scanToolCall('read_file', {
      path: '../../../../etc/passwd',
    });
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'MCP-001')).toBe(true);
    expect(events.length).toBeGreaterThan(0);
    expect(events[0].source).toBe('mcp-protocol');
  });

  it('should detect path traversal to SSH keys', () => {
    clearEvents();
    const result = interceptor.scanToolCall('read_file', {
      path: '../../../home/user/.ssh/id_rsa',
    });
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'MCP-001')).toBe(true);
  });

  // --- Command Injection ---

  it('should detect command injection with semicolon (MCP-002)', () => {
    clearEvents();
    const result = interceptor.scanToolCall('execute', {
      command: 'echo hello; cat /etc/shadow',
    });
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'MCP-002')).toBe(true);
  });

  it('should detect command injection with pipe', () => {
    clearEvents();
    const result = interceptor.scanToolCall('execute', {
      command: 'ls | cat /etc/passwd',
    });
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'MCP-002')).toBe(true);
  });

  it('should detect command injection with backticks', () => {
    clearEvents();
    const result = interceptor.scanToolCall('execute', {
      command: 'echo `whoami`',
    });
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'MCP-002')).toBe(true);
  });

  // --- SSRF ---

  it('should detect SSRF to cloud metadata (MCP-003)', () => {
    clearEvents();
    const result = interceptor.scanToolCall('fetch_url', {
      url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    });
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'MCP-003')).toBe(true);
  });

  it('should detect SSRF to localhost', () => {
    clearEvents();
    const result = interceptor.scanToolCall('fetch_url', {
      url: 'http://localhost:9000/admin',
    });
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'MCP-003')).toBe(true);
  });

  // --- Tool Allowlist ---

  it('should flag tool not in allowlist', async () => {
    clearEvents();
    const restricted = new MCPProtocolInterceptor(engine, ['read_file', 'search']);
    await restricted.start();
    const result = restricted.scanToolCall('execute', { command: 'ls' });
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'MCP-ALLOWLIST')).toBe(true);
    await restricted.stop();
  });

  it('should allow tool in allowlist with clean parameters', async () => {
    clearEvents();
    const restricted = new MCPProtocolInterceptor(engine, ['read_file', 'search']);
    await restricted.start();
    const result = restricted.scanToolCall('read_file', { path: './data/report.txt' });
    expect(result.detected).toBe(false);
    await restricted.stop();
  });

  // --- Clean Parameters ---

  it('should not flag normal file reads', () => {
    clearEvents();
    const result = interceptor.scanToolCall('read_file', {
      path: './src/index.ts',
    });
    expect(result.detected).toBe(false);
  });

  it('should not flag normal commands', () => {
    clearEvents();
    const result = interceptor.scanToolCall('execute', {
      command: 'npm test',
    });
    expect(result.detected).toBe(false);
  });
});
