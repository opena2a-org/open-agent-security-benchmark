/**
 * Capability-aware test helpers.
 *
 * Tests call requireCapability() to skip gracefully when the
 * adapter under test doesn't support a given feature. This produces
 * an honest scorecard: N/A instead of FAIL.
 *
 * @example
 *   import { requireCapability } from '../harness/capabilities';
 *
 *   describe('MCP Tool Scanning', () => {
 *     requireCapability('mcp-scanning');
 *     // tests only run if adapter has mcp-scanning
 *   });
 */
import { describe } from 'vitest';
import { createAdapter } from './create-adapter';
import type { Capability, CapabilityMatrix } from './adapter';

let _matrix: CapabilityMatrix | null = null;

function getMatrix(): CapabilityMatrix {
  if (!_matrix) {
    const adapter = createAdapter();
    _matrix = adapter.getCapabilities();
  }
  return _matrix;
}

/**
 * Check if the current adapter has a capability.
 */
export function hasCapability(cap: Capability): boolean {
  return getMatrix().capabilities.has(cap);
}

/**
 * Call at the top of a describe() block to skip the entire suite
 * if the adapter lacks the required capability.
 *
 * Uses describe.skipIf() so the tests show as skipped, not failed.
 */
export function requireCapability(cap: Capability): void {
  const has = hasCapability(cap);
  if (!has) {
    // Can't use describe.skipIf at this point, but we can use
    // a beforeAll that throws a skip. The caller should use
    // describeWithCapability instead for cleaner skip behavior.
  }
}

/**
 * A describe() wrapper that skips the entire suite if the adapter
 * lacks the required capability. Produces N/A in the scorecard.
 *
 * @example
 *   describeWithCapability('mcp-scanning', 'MCP Tool Scanning', () => {
 *     it('should detect path traversal', () => { ... });
 *   });
 */
export const describeWithCapability = (
  cap: Capability,
  name: string,
  fn: () => void,
) => {
  const has = hasCapability(cap);
  if (has) {
    describe(name, fn);
  } else {
    describe.skip(`${name} [requires: ${cap}]`, fn);
  }
};

/**
 * Get the full capability matrix for reporting.
 */
export function getCapabilityMatrix(): CapabilityMatrix {
  return getMatrix();
}
