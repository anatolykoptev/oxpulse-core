// Canonical base64url encode/decode for @oxpulse/identity.
//
// Previously duplicated between device-identity.ts and host-identity.ts
// (identical implementations). Extracted here as the single canonical copy
// per identity-extraction-adr.md §9 "base64url canonicalization".
//
// Other workspace packages (e.g. webrtc-keys-wire.ts) have their own copies —
// a workspace-wide sweep is tracked separately, not bundled here.

export function toBase64url(bytes: Uint8Array): string {
	let s = '';
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s)
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
}

export function fromBase64url(s: string): Uint8Array {
	// Restore padding
	const pad = s.length % 4;
	if (pad) s += '='.repeat(4 - pad);
	// Convert base64url to base64
	const base64 = s.replace(/-/g, '+').replace(/_/g, '/');
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}
