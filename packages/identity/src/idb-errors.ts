/** Sentinel error thrown when IndexedDB is unavailable (in-app WebView, private mode).
 *
 *  Extracted into a standalone module so both the identity package and the
 *  web/ app import the *same class reference* — enabling cross-module
 *  `instanceof` checks to work correctly. Two separately declared classes
 *  with identical names are distinct object identities in JS; `instanceof`
 *  would silently return false for errors thrown from the other module.
 *
 *  Reasons:
 *  - `no_indexedDB`  — `globalThis.indexedDB` is absent (in-app WebView, Firefox with
 *                      indexedDB disabled, or a sandboxed worker context).
 *  - `open_failed`   — `indexedDB.open()` completed but fired `onerror` / threw
 *                      synchronously (QuotaExceededError, SecurityError in private
 *                      browsing, etc.).
 *  - `timeout`       — the probe open-request exceeded the allowed wall time
 *                      (PROBE_TIMEOUT_MS in idb-availability.ts).
 *  - `upgrade_null`  — `onupgradeneeded` fired but `ev.target.result` was null;
 *                      observed in some Instagram / TikTok in-app WebViews that
 *                      fire the upgrade callback before the DB object is ready.
 */
export class IDBUnavailableError extends Error {
	readonly reason: 'no_indexedDB' | 'open_failed' | 'timeout' | 'upgrade_null';
	constructor(reason: 'no_indexedDB' | 'open_failed' | 'timeout' | 'upgrade_null') {
		super(`IndexedDB unavailable: ${reason}`);
		this.name = 'IDBUnavailableError';
		this.reason = reason;
	}
}
