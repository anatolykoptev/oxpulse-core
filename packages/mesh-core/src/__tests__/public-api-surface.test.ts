/**
 * public-api-surface.test.ts — lock on the exported surface of this package.
 *
 * WHY THIS EXISTS
 * ---------------
 * This package is published to npm. Its callers therefore live in OTHER
 * repositories, and no repo-scoped search — grep, a call-graph tool, a
 * PageRank/dead-code score — can see them. Every such tool will confidently
 * report "zero callers" for an export whose only consumers are downstream.
 *
 * That is not hypothetical: `Inbox.evictExcess` and `Spool.evictExcess` were
 * deleted as dead code on exactly that evidence, and broke oxpulse-chat's
 * periodic eviction sweep. The tools were right about this repository and wrong
 * about the world.
 *
 * So the rule is mechanical rather than a matter of care: removing or renaming
 * anything below turns this test RED. Re-approving it is a deliberate edit to
 * the expected list in the same commit, which makes the removal visible in
 * review.
 *
 * AND MARK THE COMMIT BREAKING — `fix(mesh-core)!:` or a `BREAKING CHANGE:`
 * footer. At 0.x release-please then cuts a MINOR, so a consumer on `^0.x.y`
 * cannot silently pick up a removal in a patch. Semver permits removing public
 * API in a 0.x patch, which is exactly why it is easy to keep doing by
 * accident: `Outbox.evictExcess` and `Outbox.size` went out that way in 0.1.13
 * before anyone noticed. Decided in #60.
 *
 * The `!` goes after the SCOPE, not the type. `feat!(mesh-core):` is malformed,
 * is not recognised as breaking, and cuts an ordinary patch instead.
 *
 * ADDING an export is free: the assertions below are subset checks, not
 * equality, so growth never fails the build.
 */

import { describe, it, expect } from 'vitest';
import * as api from '../index.js';
import { Inbox } from '../mailbox/inbox.js';
import { Spool } from '../mailbox/spool.js';
import { Outbox } from '../outbox.js';
import { DedupeCache } from '../dedupe.js';
import { PeerRegistry } from '../peer-registry.js';

/** Named exports the package promises. Removing one is a breaking change. */
const REQUIRED_EXPORTS = [
  // transport façade
  'startMesh', 'stopMesh', 'onFrame', 'sendFrame', 'meshState',
  'acceptPeer', 'rejectPeer', 'getPendingHandshakes', 'onHandshakeStateChange',
  // metrics
  'setMeshMetricSink', 'emitMeshMetric',
  // framing
  'chunkFrame', 'FrameReassembler', 'FRAME_HEADER_LEN',
  // peers
  'generatePeerId', 'PeerRegistry', 'MacRotationTimer',
  // routing + delivery
  'routeOutgoing', 'onIncoming', 'bridgeSend', 'startOutboxDrainer',
  // storage
  'Outbox', 'DedupeCache',
  'MESH_OUTBOX_DB_NAME', 'MESH_OUTBOX_STORE_NAME',
  // bundles / wrap
  'composeBundle', 'composeMeshWrap', 'peelMeshWrap',
  'MESH_WRAP_MAGIC', 'MESH_WRAP_FLAG_SEALED_1TO1',
  // channels
  'channelIdHash', 'neighboringChannelIds', 'currentChannelId',
  'getRegionFallback', 'getRegionDisplayName', 'availableRegions',
  // platform
  'isInCapacitor', 'isAndroid', 'isIOS', 'isNative',
  // settings intents
  'openBluetoothSettings', 'openAppPermissionSettings',
  // crypto errors
  'NoiseStateError', 'NoiseReplayError',
  // token client
  'getToken', 'clearTokens', 'clearTokensForIdentity',
];

/**
 * Instance methods downstream calls. `evictExcess` is the reason this file
 * exists — it has no in-repo caller BY DESIGN, and that is not evidence of
 * anything. oxpulse-chat drives it from web/src/lib/chat/mesh-dedup.ts on an
 * interval, with its own cap constant, and reports the returned count.
 */
const REQUIRED_METHODS: ReadonlyArray<readonly [string, new (...a: never[]) => object, readonly string[]]> = [
  ['Inbox', Inbox, ['open', 'close', 'put', 'evictExcess']],
  ['Spool', Spool, ['open', 'close', 'put', 'evictExcess']],
  ['Outbox', Outbox, ['open', 'close', 'enqueue']],
  ['DedupeCache', DedupeCache, ['hasSeen', 'markSeen']],
  ['PeerRegistry', PeerRegistry, ['upsert', 'list', 'gc', 'clear']],
];

describe('public API surface', () => {
  it('exports every name downstream depends on', () => {
    const actual = new Set(Object.keys(api));
    const missing = REQUIRED_EXPORTS.filter((n) => !actual.has(n));
    expect(
      missing,
      `Removed from the public API: ${missing.join(', ')}. This package is published — ` +
        'a repo-scoped "no callers" result cannot justify this. Search the org, then, if the ' +
        'removal is intended, drop the name here in the SAME commit and bump accordingly.',
    ).toEqual([]);
  });

  for (const [name, ctor, methods] of REQUIRED_METHODS) {
    it(`${name} keeps its documented instance methods`, () => {
      const proto = ctor.prototype as Record<string, unknown>;
      const missing = methods.filter((m) => typeof proto[m] !== 'function');
      expect(
        missing,
        `${name} lost: ${missing.join(', ')}. See this file's header before deleting a method ` +
          'that appears to have no callers.',
      ).toEqual([]);
    });
  }
});
