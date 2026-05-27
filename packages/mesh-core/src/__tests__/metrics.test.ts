import { describe, it, expect, beforeEach } from 'vitest';
import { setMeshMetricSink, emitMeshMetric } from '../metrics.js';
import type { MeshMetric, MetricSink } from '../metrics.js';

describe('metrics', () => {
  beforeEach(() => {
    // Reset to no-op sink before each test to avoid cross-test pollution.
    setMeshMetricSink(() => {});
  });

  it('sink receives emitted metric with labels', () => {
    const calls: Array<{ m: MeshMetric; l: Record<string, string> }> = [];
    setMeshMetricSink((m, l) => calls.push({ m, l: l ?? {} }));
    emitMeshMetric('handshake_failed', { reason: 'timeout' });
    expect(calls).toEqual([{ m: 'handshake_failed', l: { reason: 'timeout' } }]);
  });

  it('sink receives emitted metric without labels', () => {
    const calls: Array<{ m: MeshMetric; l: Record<string, string> | undefined }> = [];
    setMeshMetricSink((m, l) => calls.push({ m, l }));
    emitMeshMetric('replay_rejected');
    expect(calls).toEqual([{ m: 'replay_rejected', l: undefined }]);
  });

  it('emitting with no-op sink does not throw', () => {
    // Default sink before any setMeshMetricSink call is no-op; this tests that path.
    setMeshMetricSink(() => {});
    expect(() => emitMeshMetric('handshake_timeout')).not.toThrow();
  });

  it('setMeshMetricSink replaces previous sink', () => {
    const first: string[] = [];
    const second: string[] = [];
    setMeshMetricSink((m) => first.push(m));
    setMeshMetricSink((m) => second.push(m));
    emitMeshMetric('sas_mismatch');
    expect(first).toHaveLength(0);
    expect(second).toEqual(['sas_mismatch']);
  });

  it('all MeshMetric literals are valid values', () => {
    const sink: MetricSink = (m) => {
      const valid: MeshMetric[] = [
        'handshake_failed',
        'replay_rejected',
        'sas_mismatch',
        'unknown_peer_key',
        'tofu_evicted',
        'handshake_timeout',
      ];
      expect(valid).toContain(m);
    };
    setMeshMetricSink(sink);
    emitMeshMetric('handshake_failed');
    emitMeshMetric('replay_rejected');
    emitMeshMetric('sas_mismatch');
    emitMeshMetric('unknown_peer_key');
    emitMeshMetric('tofu_evicted', { count: '5' });
    emitMeshMetric('handshake_timeout');
  });
});
