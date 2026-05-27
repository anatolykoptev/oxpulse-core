// IDB availability probe for in-app WebView degraded environments.
//
// Instagram/TikTok/Facebook in-app WebViews sometimes:
//   • set globalThis.indexedDB = undefined
//   • provide a broken IDBFactory whose .open() throws synchronously
//   • provide a frozen IDBFactory whose .open() never fires callbacks
//
// Any of these causes an uncaught TypeError at boot, preventing the SPA
// from loading at all. This probe detects all three cases within 500 ms
// so callers can fall back gracefully.
//
// Probe DB name — chosen to be obviously temporary and avoid colliding with
// any production store. The probe opens version 1 and never creates stores.
const PROBE_DB_NAME = '__oxp_idb_probe__';
const PROBE_TIMEOUT_MS = 500;

export type IDBUnavailableReason = 'no_indexedDB' | 'open_failed' | 'timeout';

/**
 * Probe whether IndexedDB is usable in the current runtime.
 *
 * Returns `true` when `indexedDB.open()` fires `onsuccess` within 500 ms.
 * Returns `false` (never throws) for:
 *   - `typeof indexedDB === 'undefined'`   → reason: `no_indexedDB`
 *   - `.open()` throws synchronously        → reason: `open_failed`
 *   - `.open()` fires `onerror`             → reason: `open_failed`
 *   - no callback within 500 ms            → reason: `timeout`
 *
 * Callers that want the failure reason can use `probeIDBAvailability()` instead.
 */
export async function isIDBAvailable(): Promise<boolean> {
	const probe = await probeIDBAvailability();
	return probe.available;
}

export interface IDBProbeResult {
	available: true;
}

export interface IDBProbeFailure {
	available: false;
	reason: IDBUnavailableReason;
}

export type IDBProbeOutcome = IDBProbeResult | IDBProbeFailure;

/**
 * Full probe — returns availability flag AND reason on failure.
 * Used by device-identity.ts to emit a bounded-label analytics event.
 */
export async function probeIDBAvailability(): Promise<IDBProbeOutcome> {
	// Guard 1: global absent entirely (some in-app WebViews)
	if (typeof indexedDB === 'undefined') {
		return { available: false, reason: 'no_indexedDB' };
	}

	return new Promise<IDBProbeOutcome>((resolve) => {
		let settled = false;
		const done = (outcome: IDBProbeOutcome) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(outcome);
		};

		// Guard 3: frozen handle — resolve to timeout after PROBE_TIMEOUT_MS
		const timer = setTimeout(() => {
			done({ available: false, reason: 'timeout' });
		}, PROBE_TIMEOUT_MS);

		let req: IDBOpenDBRequest;
		try {
			// Guard 2a: .open() throws synchronously (SecurityError in some WebViews)
			req = indexedDB.open(PROBE_DB_NAME, 1);
		} catch {
			done({ available: false, reason: 'open_failed' });
			return;
		}

		// Guard 2b: .open() fires onerror
		req.onerror = () => done({ available: false, reason: 'open_failed' });
		req.onsuccess = () => {
			// Close the probe DB immediately — we only needed the open to succeed.
			try { req.result?.close(); } catch { /* ignore */ }
			// Also attempt to delete the probe DB to avoid leaving behind a
			// spurious entry in the browser's IDB list. Fire-and-forget.
			try { indexedDB.deleteDatabase(PROBE_DB_NAME); } catch { /* ignore */ }
			done({ available: true });
		};
		req.onupgradeneeded = () => {
			// Probe DB will be created on first open — that's fine, do nothing.
		};
	});
}
