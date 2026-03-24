/**
 * ARP Adapter — Reference implementation of SecurityProductAdapter
 *
 * Wraps HackMyAgent's ARP (Agent Runtime Protection) for OASB evaluation.
 * Other vendors implement their own adapter against the same interface.
 *
 * Uses lazy require() for arp-guard so the module is only loaded when
 * this adapter is actually selected. Tests that use a different adapter
 * never trigger the arp-guard import.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { EventCollector } from './event-collector';
import type {
  SecurityProductAdapter,
  SecurityEvent,
  EnforcementResult,
  LabConfig,
  PromptScanner,
  MCPScanner,
  A2AScanner,
  PatternScanner,
  BudgetManager,
  AnomalyScorer,
  EventEngine,
  EnforcementEngine as EnforcementEngineInterface,
  ScanResult,
  ThreatPattern,
  CapabilityMatrix,
} from './adapter';

// Lazy-loaded arp-guard module
let _arp: any;
function arp(): any {
  if (!_arp) {
    _arp = require('arp-guard');
  }
  return _arp;
}

export class ArpWrapper implements SecurityProductAdapter {
  private _arpInstance: any;
  private _dataDir: string;
  readonly collector: EventCollector;

  constructor(labConfig?: LabConfig) {
    this._dataDir = labConfig?.dataDir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'arp-lab-'));

    const { AgentRuntimeProtection } = arp();

    const config = {
      agentName: 'arp-lab-target',
      agentDescription: 'Test target for ARP security lab',
      declaredCapabilities: ['file read/write', 'HTTP requests'],
      dataDir: this._dataDir,
      monitors: {
        process: {
          enabled: labConfig?.monitors?.process ?? false,
          intervalMs: labConfig?.processIntervalMs,
        },
        network: {
          enabled: labConfig?.monitors?.network ?? false,
          intervalMs: labConfig?.networkIntervalMs,
          allowedHosts: labConfig?.networkAllowedHosts,
        },
        filesystem: {
          enabled: labConfig?.monitors?.filesystem ?? false,
          watchPaths: labConfig?.filesystemWatchPaths,
          allowedPaths: labConfig?.filesystemAllowedPaths,
        },
      },
      rules: labConfig?.rules,
      intelligence: {
        enabled: labConfig?.intelligence?.enabled ?? false,
        budgetUsd: 0,
      },
      interceptors: {
        process: { enabled: labConfig?.interceptors?.process ?? false },
        network: {
          enabled: labConfig?.interceptors?.network ?? false,
          allowedHosts: labConfig?.interceptorNetworkAllowedHosts,
        },
        filesystem: {
          enabled: labConfig?.interceptors?.filesystem ?? false,
          allowedPaths: labConfig?.interceptorFilesystemAllowedPaths,
        },
      },
    };

    this._arpInstance = new AgentRuntimeProtection(config);
    this.collector = new EventCollector();

    this._arpInstance.onEvent(this.collector.eventHandler);
    this._arpInstance.onEnforcement(this.collector.enforcementHandler);
  }

  getCapabilities(): CapabilityMatrix {
    return {
      product: 'arp-guard',
      version: arp().VERSION || '0.3.0',
      capabilities: new Set([
        'process-monitoring',
        'network-monitoring',
        'filesystem-monitoring',
        'prompt-input-scanning',
        'prompt-output-scanning',
        'mcp-scanning',
        'a2a-scanning',
        'anomaly-detection',
        'budget-management',
        'enforcement-log',
        'enforcement-alert',
        'enforcement-pause',
        'enforcement-kill',
        'enforcement-resume',
        'pattern-scanning',
      ]),
    };
  }

  async start(): Promise<void> {
    await this._arpInstance.start();
  }

  async stop(): Promise<void> {
    await this._arpInstance.stop();
    this.collector.reset();
    try {
      fs.rmSync(this._dataDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup
    }
  }

  async injectEvent(event: Omit<SecurityEvent, 'id' | 'timestamp' | 'classifiedBy'>): Promise<SecurityEvent> {
    return this.getEngine().emit(event);
  }

  waitForEvent(predicate: (event: SecurityEvent) => boolean, timeoutMs: number = 10000): Promise<SecurityEvent> {
    return this.collector.waitForEvent(predicate, timeoutMs);
  }

  getEvents(): SecurityEvent[] {
    return this.collector.getEvents();
  }

  getEventsByCategory(category: string): SecurityEvent[] {
    return this.collector.eventsByCategory(category);
  }

  getEnforcements(): EnforcementResult[] {
    return this.collector.getEnforcements() as EnforcementResult[];
  }

  getEnforcementsByAction(action: string): EnforcementResult[] {
    return this.collector.enforcementsByAction(action) as EnforcementResult[];
  }

  resetCollector(): void {
    this.collector.reset();
  }

  getInstance(): any {
    return this._arpInstance;
  }

  getEventEngine(): EventEngine {
    return this._arpInstance.getEngine() as unknown as EventEngine;
  }

  getEnforcementEngine(): EnforcementEngineInterface {
    return this._arpInstance.getEnforcement() as unknown as EnforcementEngineInterface;
  }

  getEngine(): any {
    return this._arpInstance.getEngine();
  }

  getEnforcement(): any {
    return this._arpInstance.getEnforcement();
  }

  get dataDir(): string {
    return this._dataDir;
  }

  // ─── Factory Methods ────────────────────────────────────────────

  createPromptScanner(): PromptScanner {
    const { EventEngine, PromptInterceptor } = arp();
    const engine = new EventEngine({ agentName: 'oasb-prompt-test' });
    const interceptor = new PromptInterceptor(engine);
    return {
      start: () => interceptor.start(),
      stop: () => interceptor.stop(),
      scanInput: (text: string) => interceptor.scanInput(text),
      scanOutput: (text: string) => interceptor.scanOutput(text),
    };
  }

  createMCPScanner(allowedTools?: string[]): MCPScanner {
    const { EventEngine, MCPProtocolInterceptor } = arp();
    const engine = new EventEngine({ agentName: 'oasb-mcp-test' });
    const interceptor = new MCPProtocolInterceptor(engine, allowedTools);
    return {
      start: () => interceptor.start(),
      stop: () => interceptor.stop(),
      scanToolCall: (toolName: string, params: Record<string, unknown>) => interceptor.scanToolCall(toolName, params),
    };
  }

  createA2AScanner(trustedAgents?: string[]): A2AScanner {
    const { EventEngine, A2AProtocolInterceptor } = arp();
    const engine = new EventEngine({ agentName: 'oasb-a2a-test' });
    const interceptor = new A2AProtocolInterceptor(engine, trustedAgents);
    return {
      start: () => interceptor.start(),
      stop: () => interceptor.stop(),
      scanMessage: (from: string, to: string, content: string) => interceptor.scanMessage(from, to, content),
    };
  }

  createPatternScanner(): PatternScanner {
    const { scanText: _scanText, ALL_PATTERNS: _allPatterns, PATTERN_SETS: _patternSets } = arp();
    return {
      scanText: (text: string, patterns: readonly ThreatPattern[]) => _scanText(text, patterns) as ScanResult,
      getAllPatterns: () => _allPatterns as unknown as readonly ThreatPattern[],
      getPatternSets: () => _patternSets as unknown as Record<string, readonly ThreatPattern[]>,
    };
  }

  createBudgetManager(dataDir: string, config?: { budgetUsd?: number; maxCallsPerHour?: number }): BudgetManager {
    const { BudgetController } = arp();
    const controller = new BudgetController(dataDir, config);
    return {
      canAfford: (cost: number) => controller.canAfford(cost),
      record: (cost: number, tokens: number) => controller.record(cost, tokens),
      getStatus: () => controller.getStatus(),
      reset: () => controller.reset(),
    };
  }

  createAnomalyScorer(): AnomalyScorer {
    const { AnomalyDetector } = arp();
    const detector = new AnomalyDetector();
    return {
      score: (event: SecurityEvent) => detector.score(event),
      record: (event: SecurityEvent) => detector.record(event),
      getBaseline: (source: string) => detector.getBaseline(source),
      reset: () => detector.reset(),
    };
  }
}
