#!/usr/bin/env node
/**
 * Merge corpus batches into a single dataset file.
 *
 * Reads all corpus/batch-*.json and corpus/v1.json,
 * deduplicates by ID, and writes corpus/v2.json.
 *
 * Usage: node scripts/merge-corpus.mjs
 */

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const corpusDir = join(__dirname, '..', 'corpus');

const ATTACK_CATEGORIES = [
  'supply_chain', 'prompt_injection', 'credential_exfiltration', 'heartbeat_rce',
  'unicode_stego', 'privilege_escalation', 'persistence', 'social_engineering',
  'data_exfiltration',
];

// Load v1 as base
const v1 = JSON.parse(readFileSync(join(corpusDir, 'v1.json'), 'utf-8'));
const allSamples = new Map();

// Add v1 samples
for (const s of v1.samples) {
  allSamples.set(s.id, s);
}
console.log(`v1.json: ${v1.samples.length} samples`);

// Load all batch files
const batchFiles = readdirSync(corpusDir).filter(f => f.startsWith('batch-') && f.endsWith('.json'));
for (const file of batchFiles.sort()) {
  try {
    const batch = JSON.parse(readFileSync(join(corpusDir, file), 'utf-8'));
    const samples = Array.isArray(batch) ? batch : batch.samples || [];
    let added = 0;
    for (const s of samples) {
      if (!allSamples.has(s.id)) {
        allSamples.set(s.id, s);
        added++;
      }
    }
    console.log(`${file}: ${samples.length} samples (${added} new)`);
  } catch (err) {
    console.error(`Failed to load ${file}: ${err.message}`);
  }
}

// Load registry corpus if it exists
try {
  const registry = JSON.parse(readFileSync(join(corpusDir, 'registry-corpus.json'), 'utf-8'));
  let added = 0;
  for (const s of registry.samples) {
    if (!allSamples.has(s.id)) {
      allSamples.set(s.id, s);
      added++;
    }
  }
  console.log(`registry-corpus.json: ${registry.samples.length} samples (${added} new)`);
} catch { /* not yet exported */ }

// Build v2 dataset
const samples = [...allSamples.values()];
const malicious = samples.filter(s => s.label === 'malicious');
const benign = samples.filter(s => s.label === 'benign');
const edgeCases = samples.filter(s => s.label === 'edge_case');

const categoryCounts = {};
for (const cat of ATTACK_CATEGORIES) {
  categoryCounts[cat] = malicious.filter(s => s.category === cat).length;
}

const v2 = {
  version: 'v2.0',
  createdAt: new Date().toISOString(),
  totalSamples: samples.length,
  maliciousSamples: malicious.length,
  benignSamples: benign.length,
  edgeCaseSamples: edgeCases.length,
  categoryCounts,
  samples,
};

const outputPath = join(corpusDir, 'v2.json');
writeFileSync(outputPath, JSON.stringify(v2, null, 2));

console.log(`\nWrote ${outputPath}`);
console.log(`Total: ${v2.totalSamples} samples`);
console.log(`  Malicious: ${v2.maliciousSamples} (${JSON.stringify(categoryCounts)})`);
console.log(`  Benign: ${v2.benignSamples}`);
console.log(`  Edge cases: ${v2.edgeCaseSamples}`);
