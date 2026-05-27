// Storage key pinning test — guards against accidental rename of load-bearing
// IDB store name and key names that existing users depend on.
//
// Pre-existing user data is stored under these exact strings. If any of these
// change, every installed user's identity is orphaned (device-key becomes
// unreadable, a new identity is silently created on the next load, and the user
// loses their handle + all associated profile data).
//
// See identity-extraction-adr.md §3.4 for the rationale and §6 Risk R2.
// These values MUST match what device-identity.ts writes to IndexedDB.

import { describe, it, expect } from 'vitest';
import { IDB_DB_NAME, IDB_STORE_NAME } from '../device-identity.js';

describe('storage key pinning (ADR §3.4 — NEVER change these values)', () => {
	it('IDB database name is pinned to legacy value', () => {
		// Changing this orphans all installed users' identities.
		// See identity-extraction-adr.md §3.4 Risk R2.
		expect(IDB_DB_NAME).toBe('oxpulse-device-id');
	});

	it('IDB object store name is pinned to legacy value', () => {
		// Changing this orphans all installed users' identities.
		expect(IDB_STORE_NAME).toBe('identity');
	});
});
