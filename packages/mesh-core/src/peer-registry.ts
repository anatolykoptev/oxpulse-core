import { PEER_ID_BYTES } from './constants.js';

export interface Peer {
  id: Uint8Array;       // 8 bytes
  idHex: string;
  mac: string;          // observed MAC at last sighting (rotates)
  lastSeen: number;
  rssi?: number;
}

export function generatePeerId(): Uint8Array {
  const a = new Uint8Array(PEER_ID_BYTES);
  crypto.getRandomValues(a);
  return a;
}

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export class PeerRegistry {
  private byId = new Map<string, Peer>();
  private ttlMs: number;

  constructor(opts: { ttlMs?: number } = {}) {
    this.ttlMs = opts.ttlMs ?? 120_000;
  }

  upsert(id: Uint8Array, mac: string, rssi?: number): void {
    const idHex = hex(id);
    const existing = this.byId.get(idHex);
    if (existing) {
      existing.lastSeen = Date.now();
      existing.mac = mac;
      if (rssi !== undefined) existing.rssi = rssi;
    } else {
      this.byId.set(idHex, { id, idHex, mac, lastSeen: Date.now(), rssi });
    }
  }

  remove(idHex: string): void {
    this.byId.delete(idHex);
  }

  gc(now: number = Date.now()): void {
    for (const [k, p] of this.byId) {
      if (now - p.lastSeen > this.ttlMs) this.byId.delete(k);
    }
  }

  list(): Peer[] {
    return [...this.byId.values()];
  }

  clear(): void {
    this.byId.clear();
  }
}
