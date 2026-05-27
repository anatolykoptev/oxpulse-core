/**
 * mailbox barrel — re-exports outbox + dedup primitives under a single namespace.
 * Existing top-level imports (`@oxpulse/mesh-core` → `Outbox`, `DedupeCache`) stay valid;
 * this barrel groups them for new code that wants to import the full mailbox surface
 * (inbox, spool added in subsequent tasks).
 */
export { Outbox, MAX_OUTBOX_ATTEMPTS, MESH_OUTBOX_DB_NAME, MESH_OUTBOX_STORE_NAME } from '../outbox.ts';
export type { OutboxEntry } from '../outbox.ts';
export { DedupeCache } from '../dedupe.ts';
export type { DedupeCacheOptions } from '../dedupe.ts';
export { Inbox, MESH_INBOX_DB_NAME, MESH_INBOX_STORE_NAME } from './inbox.ts';
export type { InboxEntry } from './inbox.ts';
export { Spool, MESH_SPOOL_DB_NAME, MESH_SPOOL_STORE_NAME } from './spool.ts';
export type { SpoolEntry } from './spool.ts';
export { BloomDedup, MESH_BLOOM_DB_NAME, MESH_BLOOM_STORE_NAME } from './dedup-bloom.ts';
export type { BloomDedupOptions } from './dedup-bloom.ts';
