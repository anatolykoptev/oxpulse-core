// Analytics injection shim for @oxpulse/identity.
//
// device-identity.ts calls track('client.identity_*', ...) from
// web/src/lib/tracker.ts. tracker.ts has 20+ unrelated consumers
// (call metrics, payments) — moving it into identity would either
// duplicate the module or invert the dependency (identity → web), both wrong.
//
// Solution: identity exports a setter. web/src/hooks.client.ts (or +layout.svelte
// boot path) calls setIdentityTracker(track) once at startup.
// Mesh-core leaves the default noop (it has its own metrics path).
// Test files set their own spy.
//
// See identity-extraction-adr.md §3.2 for rationale.

export type IdentityTracker = (event: string, roomId?: string, payload?: Record<string, unknown>) => void;

// noop default — safe until web/ wires setIdentityTracker at boot
let tracker: IdentityTracker = () => {};

export function setIdentityTracker(fn: IdentityTracker): void {
	tracker = fn;
}

/** Emit an analytics event via the injected tracker. Internal use only. */
export function emit(event: string, roomId?: string, payload?: Record<string, unknown>): void {
	tracker(event, roomId, payload);
}
