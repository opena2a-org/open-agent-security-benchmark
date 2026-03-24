/**
 * Adapter factory — selects which security product adapter to use.
 *
 * Set OASB_ADAPTER env var to choose:
 *   - "arp" (default) — uses arp-guard (must be installed)
 *   - "llm-guard" — uses theRizwan/llm-guard
 *   - path to a JS/TS module that exports a class implementing SecurityProductAdapter
 *
 * All test files import from here instead of instantiating adapters directly.
 */
import type { SecurityProductAdapter, LabConfig } from './adapter';

// Eagerly resolve the adapter class at import time.
// This file is only imported by tests that need the adapter,
// so the cost is acceptable. Each wrapper handles lazy loading internally.
import { ArpWrapper } from './arp-wrapper';
import { LLMGuardWrapper } from './llm-guard-wrapper';
import { RebuffWrapper } from './rebuff-wrapper';

let AdapterClass: new (config?: LabConfig) => SecurityProductAdapter;

const adapterName = process.env.OASB_ADAPTER || 'arp';

switch (adapterName) {
  case 'arp':
    AdapterClass = ArpWrapper;
    break;
  case 'llm-guard':
    AdapterClass = LLMGuardWrapper;
    break;
  case 'rebuff':
    AdapterClass = RebuffWrapper;
    break;
  default: {
    // Custom adapter — loaded at module level
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require(adapterName);
    const Cls = mod.default || mod.Adapter || mod[Object.keys(mod)[0]];
    if (!Cls || typeof Cls !== 'function') {
      throw new Error(`Module "${adapterName}" does not export an adapter class`);
    }
    AdapterClass = Cls;
    break;
  }
}

/**
 * Create a configured adapter instance.
 * Uses OASB_ADAPTER env var to select the product under test.
 */
export function createAdapter(config?: LabConfig): SecurityProductAdapter {
  return new AdapterClass(config);
}
