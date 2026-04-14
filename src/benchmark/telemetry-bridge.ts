/**
 * OASB Telemetry Bridge
 *
 * Reports NanoMind classification stats from benchmark runs to the Registry.
 * Uses the shared telemetry library from hackmyagent/nanomind-core.
 * Fire-and-forget: never blocks or fails the benchmark.
 */

import type { ScannerResult } from './types.js';

const TOOL_ID = 'oasb';

// Lazy-loaded telemetry module from HMA
let telemetryModule: any = null;
let loadAttempted = false;

async function loadTelemetry(): Promise<any> {
  if (telemetryModule) return telemetryModule;
  if (loadAttempted) return null;
  loadAttempted = true;

  try {
    const path = require('path');
    const telemetryPath = path.resolve(
      __dirname, '..', '..', '..', 'hackmyagent', 'dist', 'nanomind-core', 'telemetry', 'index.js',
    );
    telemetryModule = await import(telemetryPath);
    return telemetryModule;
  } catch {
    return null;
  }
}

/**
 * Report benchmark scan results as Tier 1 telemetry.
 * Fire-and-forget: never throws.
 */
export async function reportBenchmarkTelemetry(
  results: ScannerResult[],
  adapterId: string,
  adapterVersion: string,
): Promise<void> {
  try {
    const telem = await loadTelemetry();
    if (!telem || !telem.isEnabled(TOOL_ID)) return;

    const config = telem.loadConfig(TOOL_ID);
    const stats = results.map(r =>
      telem.createStat(
        r.sampleId || '',
        'benchmark_sample',
        r.category || r.verdict || 'unknown',
        r.confidence || 0,
        r.verdict || 'unknown',
        adapterVersion,
        TOOL_ID,
      ),
    );

    if (stats.length > 0) {
      await telem.submitStats(stats, config);
    }
  } catch {
    // Telemetry must never break the benchmark.
  }
}
