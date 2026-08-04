/**
 * #45 — Bloom filter params change must emit a metric, not just console.warn.
 *
 * When Bloom filter parameters (m, k) change between sessions, the existing bits
 * array is discarded. That silent state loss must be observable via a metric so
 * operators can detect config drift in production telemetry.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import 'fake-indexeddb/auto';
import { BloomDedup } from '../mailbox/dedup-bloom.ts';
import { setMeshMetricSink, emitMeshMetric } from '../metrics.js';
import type { MeshMetric } from '../metrics.js';

describe('BloomDedup params-change metric (#45)', () => {
  beforeEach(() => {
    setMeshMetricSink(() => {});
  });

  it('emits bloom_params_changed with old/new m,k labels when params differ', async () => {
    const dbName = 'test-bloom-params-' + Math.random();

    // First instance: capacity=100, initializes fresh state.
    const bloom1 = new BloomDedup({ dbName, capacity: 100, fpRate: 0.01 });
    await bloom1.open();
    bloom1.markSeen('persisted-1');
    await bloom1.flush();
    const oldM = (bloom1 as unknown as { m: number }).m;
    const oldK = (bloom1 as unknown as { k: number }).k;
    bloom1.close();

    // Capture metrics emitted during the second open().
    const calls: Array<{ m: MeshMetric; l: Record<string, string> | undefined }> = [];
    setMeshMetricSink((m, l) => calls.push({ m, l }));

    // Second instance: capacity=200 → different m, so params drift is detected.
    const bloom2 = new BloomDedup({ dbName, capacity: 200, fpRate: 0.01 });
    await bloom2.open();
    const newM = (bloom2 as unknown as { m: number }).m;
    const newK = (bloom2 as unknown as { k: number }).k;
    bloom2.close();

    const driftCall = calls.find((c) => c.m === 'bloom_params_changed');
    expect(driftCall).toBeDefined();
    expect(driftCall!.l).toEqual({
      old_m: String(oldM),
      new_m: String(newM),
      old_k: String(oldK),
      new_k: String(newK),
    });
  });

  it('does not emit bloom_params_changed when params are unchanged', async () => {
    const dbName = 'test-bloom-same-' + Math.random();

    const bloom1 = new BloomDedup({ dbName, capacity: 100, fpRate: 0.01 });
    await bloom1.open();
    await bloom1.flush();
    bloom1.close();

    const calls: Array<{ m: MeshMetric; l: Record<string, string> | undefined }> = [];
    setMeshMetricSink((m, l) => calls.push({ m, l }));

    const bloom2 = new BloomDedup({ dbName, capacity: 100, fpRate: 0.01 });
    await bloom2.open();
    bloom2.close();

    expect(calls.find((c) => c.m === 'bloom_params_changed')).toBeUndefined();
  });

  it('bloom_params_changed is a valid MeshMetric literal', () => {
    // Compile-time check: if the literal is not in the union, this fails to typecheck.
    const m: MeshMetric = 'bloom_params_changed';
    expect(m).toBe('bloom_params_changed');
    // Ensure emitMeshMetric accepts it.
    expect(() => emitMeshMetric('bloom_params_changed', { old_m: '1', new_m: '2', old_k: '3', new_k: '4' })).not.toThrow();
  });
});
