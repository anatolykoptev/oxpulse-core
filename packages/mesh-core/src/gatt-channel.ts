import { BleClient } from '@capacitor-community/bluetooth-le';
import {
  MESH_SERVICE_UUID,
  MESH_RX_CHARACTERISTIC_UUID,
  MESH_TX_CHARACTERISTIC_UUID,
  GATT_MTU_DEFAULT,
  GATT_MTU_TARGET,
} from './constants.js';

const CONNECT_TIMEOUT_MS = 5_000;
const WRITE_TIMEOUT_MS = 2_000;

/**
 * Race a promise against a timeout.
 * Rejects with an Error if the timeout fires first.
 */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms),
    ),
  ]);
}

/**
 * Connect to a BLE peripheral and discover its services.
 *
 * @param deviceId   BleClient device identifier.
 * @param onDisconnect Optional callback invoked when the device disconnects
 *   unexpectedly. The deviceId is passed for caller convenience.
 */
export async function connect(deviceId: string, onDisconnect?: () => void): Promise<void> {
  await withTimeout(
    BleClient.connect(deviceId, onDisconnect ? () => onDisconnect() : undefined),
    CONNECT_TIMEOUT_MS,
    `connect(${deviceId})`,
  );
  // Discover services so characteristics are queryable via getServices().
  await BleClient.discoverServices(deviceId);
}

/** Disconnect from a peripheral. Safe to call on an already-disconnected device. */
export async function disconnect(deviceId: string): Promise<void> {
  await BleClient.disconnect(deviceId);
}

/**
 * Write a chunk to the RX characteristic (peer→us direction on the remote).
 * Uses write-without-response for throughput; each chunk must fit within the
 * negotiated MTU minus 3 bytes of ATT overhead.
 */
export async function writeRx(deviceId: string, chunk: Uint8Array): Promise<void> {
  const dataView = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  await withTimeout(
    BleClient.writeWithoutResponse(
      deviceId,
      MESH_SERVICE_UUID,
      MESH_RX_CHARACTERISTIC_UUID,
      dataView,
    ),
    WRITE_TIMEOUT_MS,
    `writeRx(${deviceId})`,
  );
}

/**
 * Subscribe to TX characteristic notifications (us→peer direction on the remote).
 *
 * @returns Unsubscribe function — call it to stop notifications and clean up.
 */
export async function subscribeTx(
  deviceId: string,
  onChunk: (chunk: Uint8Array) => void,
): Promise<() => Promise<void>> {
  await BleClient.startNotifications(
    deviceId,
    MESH_SERVICE_UUID,
    MESH_TX_CHARACTERISTIC_UUID,
    (v: DataView) => {
      onChunk(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
    },
  );

  return async () => {
    await BleClient.stopNotifications(deviceId, MESH_SERVICE_UUID, MESH_TX_CHARACTERISTIC_UUID);
  };
}

/**
 * Query the negotiated MTU for a connected device.
 *
 * The BleClient library exposes `getMtu` (not `requestMtu`) — the MTU is
 * negotiated automatically by the OS during connection. We read back the
 * result and return it; if the call fails (e.g. unsupported on older Android)
 * we fall back to GATT_MTU_DEFAULT.
 *
 * Callers should subtract 3 (ATT overhead) from the returned value to obtain
 * the maximum payload size per write-without-response call.
 *
 * Target: GATT_MTU_TARGET (247). Actual value depends on device negotiation.
 */
export async function negotiateMtu(deviceId: string): Promise<number> {
  try {
    const mtu = await BleClient.getMtu(deviceId);
    // Clamp to sensible range in case the device reports an unusual value.
    if (mtu > 0 && mtu <= GATT_MTU_TARGET) return mtu;
    if (mtu > GATT_MTU_TARGET) return GATT_MTU_TARGET;
  } catch {
    // Device or OS does not support MTU query — use baseline.
  }
  return GATT_MTU_DEFAULT;
}
