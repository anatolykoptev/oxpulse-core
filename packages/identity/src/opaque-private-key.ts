// OpaquePrivateKey — a wrapper around raw secret bytes that prevents
// accidental exfiltration through logging or serialization.
//
// Used to shield the Ed25519 seed resident in DeviceIdentity.privateKeySeed
// (ADR-5). X25519 DH scalar adoption is a followup.
//
// Hardening surfaces:
//   - private `#bytes` field — JSON.stringify cannot reach it (own-enumerable
//     only; private fields are non-enumerable and invisible to Reflect.keys).
//   - toJSON() throws — defeats JSON.stringify(op) and JSON.stringify({ key: op }).
//   - toString() redacts — defeats template-literal interpolation and String(op).
//   - Symbol.for('nodejs.util.inspect.custom') redacts — Node's util.inspect
//     (and pino, which consults the same symbol) print the redaction instead
//     of the bytes. Useful in vitest/Node test output.
//   - bytes() returns a FRESH copy on every call — callers cannot retain an
//     alias that defeats zeroization intent.
//   - constructor defensive-copies its input — the caller cannot zero/mutate
//     the underlying buffer after handoff.
//
// Accepted limitation (same as the prior art): the raw bytes remain resident
// in the JS heap and cannot be explicitly zeroed (no zeroize equivalent). The
// wrapper's job is to stop *accidental* exfiltration, not a determined
// in-process attacker.

/**
 * Wraps raw secret bytes and prevents accidental exfiltration through
 * logging/serialization. See module docstring for the hardening surfaces.
 */
export class OpaquePrivateKey {
	readonly #bytes: Uint8Array;

	constructor(bytes: Uint8Array) {
		// Defensive copy so the caller can't zero/mutate the underlying buffer
		// after handoff.
		this.#bytes = new Uint8Array(bytes);
	}

	/**
	 * Returns a FRESH copy of the secret bytes on every call.
	 *
	 * Returning a copy (rather than the internal buffer) prevents callers from
	 * retaining an alias that defeats zeroization intent — a caller that
	 * discards its copy after use lets that copy be GC'd independently of the
	 * canonical material.
	 */
	bytes(): Uint8Array {
		return new Uint8Array(this.#bytes);
	}

	/** Defeats JSON.stringify(op) and JSON.stringify({ key: op }). */
	toJSON(): never {
		throw new Error('OpaquePrivateKey is not serializable');
	}

	toString(): string {
		return '[OpaquePrivateKey REDACTED]';
	}

	// Node's util.inspect and pino both consult this symbol.
	[Symbol.for('nodejs.util.inspect.custom')](): string {
		return '[OpaquePrivateKey REDACTED]';
	}
}
