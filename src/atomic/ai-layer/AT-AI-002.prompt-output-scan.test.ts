// AT-AI-002: Prompt Output Scanning
// ATLAS: AML.T0057 (Data Leakage)
// OWASP: A04 (Output Handling)
//
// Verifies that PromptInterceptor.scanOutput() detects leaked secrets,
// PII, and system prompts in LLM responses before they reach the user.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { EventEngine, PromptInterceptor, type ARPEvent } from '@opena2a/arp';

describe('AT-AI-002: Prompt Output Scanning', () => {
  let engine: EventEngine;
  let interceptor: PromptInterceptor;
  let events: ARPEvent[];

  beforeAll(async () => {
    engine = new EventEngine({ agentName: 'oasb-output-test' });
    interceptor = new PromptInterceptor(engine);
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

  // --- API Key Leaks ---

  it('should detect OpenAI API key in output (OL-001)', () => {
    clearEvents();
    const result = interceptor.scanOutput(
      'Here are your credentials: API key is sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234'
    );
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'OL-001')).toBe(true);
    expect(events.length).toBeGreaterThan(0);
    expect(events[0].data.direction).toBe('output');
  });

  it('should detect AWS secret key pattern in output (OL-001)', () => {
    clearEvents();
    const result = interceptor.scanOutput(
      'The AWS credentials are: AKIAIOSFODNN7EXAMPLE and wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    );
    expect(result.detected).toBe(true);
  });

  // --- PII Leaks ---

  it('should detect PII in output (OL-002)', () => {
    clearEvents();
    const result = interceptor.scanOutput(
      'The user SSN is 123-45-6789 and their credit card number is 4111-1111-1111-1111.'
    );
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'OL-002')).toBe(true);
  });

  // --- System Prompt Leak ---

  it('should detect system prompt leak in output (OL-003)', () => {
    clearEvents();
    const result = interceptor.scanOutput(
      'My system prompt says: "You are a helpful assistant. Your API key is stored in the environment."'
    );
    expect(result.detected).toBe(true);
    expect(result.matches.some(m => m.pattern.id === 'OL-003')).toBe(true);
  });

  // --- Clean Output ---

  it('should not flag normal assistant responses', () => {
    clearEvents();
    const result = interceptor.scanOutput(
      'Here is a Python function to sort a list:\n\ndef sort_list(items):\n    return sorted(items)'
    );
    expect(result.detected).toBe(false);
  });

  it('should not flag technical code examples', () => {
    clearEvents();
    const result = interceptor.scanOutput(
      'To configure Express.js CORS, use the cors middleware:\nconst cors = require("cors");\napp.use(cors());'
    );
    expect(result.detected).toBe(false);
  });
});
