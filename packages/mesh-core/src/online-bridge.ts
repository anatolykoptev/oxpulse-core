/**
 * online-bridge.ts — B-4 Phase.
 *
 * POST encoded mesh-bundle bytes to /api/sdk/mesh/relay with a JWT.
 * Maps server result labels to typed error reasons.
 */

export type BridgeOkResult = { ok: true; seq?: number };
export type BridgeErrorResult = {
  ok: false;
  status: number;
  reason: 'bad_jwt' | 'bad_signature' | 'bad_bundle' | 'bad_freshness' |
          'channel_mismatch' | 'rate_limited' | 'disabled' | 'fanout_error' |
          'network_error' | 'unknown';
};
export type BridgeResult = BridgeOkResult | BridgeErrorResult;

export interface BridgeSendArgs {
  bundle: Uint8Array;
  jwt: string;
  /**
   * Optional callback invoked exactly once per bridgeSend call with the result.
   * Use this to wire metrics/logging without coupling the bridge to any specific
   * telemetry pipeline.
   */
  onResult?: (result: BridgeResult) => void;
}

type ServerResult = string;

function mapReason(status: number, serverResult: ServerResult): BridgeErrorResult['reason'] {
  if (status === 429) return 'rate_limited';
  if (status === 401) return 'bad_jwt';
  const map: Record<string, BridgeErrorResult['reason']> = {
    bad_jwt: 'bad_jwt',
    bad_signature: 'bad_signature',
    bad_bundle: 'bad_bundle',
    bad_freshness: 'bad_freshness',
    channel_mismatch: 'channel_mismatch',
    rate_limited: 'rate_limited',
    disabled: 'disabled',
    fanout_error: 'fanout_error',
  };
  return map[serverResult] ?? 'unknown';
}

/**
 * POST bundle bytes to /api/sdk/mesh/relay.
 * Returns a typed result — never throws.
 * Calls onResult (if provided) exactly once with the final result on every path:
 * success, any rejection reason, and network error.
 */
export async function bridgeSend(args: BridgeSendArgs): Promise<BridgeResult> {
  const { bundle, jwt, onResult } = args;

  const emit = (result: BridgeResult): BridgeResult => {
    try {
      onResult?.(result);
    } catch {
      // onResult must never propagate — bridgeSend contract says never throws.
      // Swallow silently; caller is responsible for onResult not throwing.
    }
    return result;
  };

  try {
    const body = bundle.buffer.slice(bundle.byteOffset, bundle.byteOffset + bundle.byteLength) as ArrayBuffer;
    const resp = await fetch('/api/sdk/mesh/relay', {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        authorization: `Bearer ${jwt}`,
      },
      body,
    });

    let serverBody: { result?: string; seq?: number } = {};
    try {
      serverBody = await resp.json() as typeof serverBody;
    } catch {
      // Non-JSON body — treat as empty
    }

    if (resp.ok && (serverBody.result === 'ok' || !serverBody.result)) {
      return emit({ ok: true, seq: serverBody.seq });
    }

    return emit({
      ok: false,
      status: resp.status,
      reason: mapReason(resp.status, serverBody.result ?? ''),
    });
  } catch {
    return emit({ ok: false, status: 0, reason: 'network_error' });
  }
}
