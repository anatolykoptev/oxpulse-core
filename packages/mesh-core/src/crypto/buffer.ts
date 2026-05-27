/**
 * Defensive ArrayBuffer copy from a Uint8Array view.
 *
 * Required by TS 6 strict mode when calling WebCrypto APIs that accept
 * `BufferSource` — `Uint8Array<ArrayBufferLike>` (which Node `types`
 * produces) is not assignable to `ArrayBufferView<ArrayBuffer>` because of
 * SharedArrayBuffer incompatibility. The slice() also defeats buffer
 * aliasing — caller may freely mutate the returned ArrayBuffer without
 * affecting the source.
 */
export function toBufferSource(a: Uint8Array): ArrayBuffer {
  return a.buffer.slice(a.byteOffset, a.byteOffset + a.byteLength) as ArrayBuffer;
}
