// Cross-module instanceof check for IDBUnavailableError.
//
// This test guards against the dual-declaration footgun: if two modules each
// declare their own class with the same name, `instanceof` returns false for
// errors thrown from the other module (they are distinct JS class objects).
// The fix — a single canonical class in idb-errors.ts re-exported from the
// package index — is verified here.
//
// See PR #1122 review followup (chore/web-idb-cleanup-followups).

import { describe, it, expect } from 'vitest';
import { IDBUnavailableError } from '../idb-errors.js';
import { IDBUnavailableError as IndexExport } from '../index.js';

describe('IDBUnavailableError', () => {
	it('has correct name and message', () => {
		const e = new IDBUnavailableError('timeout');
		expect(e.name).toBe('IDBUnavailableError');
		expect(e.message).toBe('IndexedDB unavailable: timeout');
		expect(e.reason).toBe('timeout');
		expect(e instanceof Error).toBe(true);
	});

	it('instanceof check works for all reason variants', () => {
		for (const reason of ['no_indexedDB', 'open_failed', 'timeout', 'upgrade_null'] as const) {
			const e = new IDBUnavailableError(reason);
			expect(e instanceof IDBUnavailableError).toBe(true);
			expect(e.reason).toBe(reason);
		}
	});

	it('instanceof check works cross-module (index re-export === idb-errors direct)', () => {
		// IDBUnavailableError from index.ts must be the SAME class object as from
		// idb-errors.ts directly — otherwise `instanceof` would silently return false
		// when web/ catches an error thrown from packages/identity code.
		expect(IndexExport).toBe(IDBUnavailableError);

		const fromDirect = new IDBUnavailableError('open_failed');
		expect(fromDirect instanceof IndexExport).toBe(true);

		const fromIndex = new IndexExport('no_indexedDB');
		expect(fromIndex instanceof IDBUnavailableError).toBe(true);
	});
});
