import { describe, it, expect } from 'vitest';
import { Outbox, MESH_OUTBOX_DB_NAME, MAX_OUTBOX_ATTEMPTS, DedupeCache } from '../mailbox/index.ts';

describe('mailbox barrel', () => {
  it('re-exports Outbox and DedupeCache from mailbox/', () => {
    expect(typeof Outbox).toBe('function');
    expect(typeof DedupeCache).toBe('function');
    expect(MESH_OUTBOX_DB_NAME).toBe('mesh-router-outbox');
    expect(MAX_OUTBOX_ATTEMPTS).toBe(8);
  });
});
