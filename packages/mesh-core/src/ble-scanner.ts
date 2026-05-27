import { BleClient } from '@capacitor-community/bluetooth-le';
import { MESH_SERVICE_UUID, PEER_ID_BYTES } from './constants.js';

export interface PeerSighting {
  /** BleClient device identifier (MAC on Android, UUID handle on iOS). */
  deviceId: string;
  /** Received Signal Strength Indication in dBm. */
  rssi: number;
  /** 8-byte ephemeral peer identifier parsed from service-data advertisement. */
  peerId: Uint8Array;
}

let initialized = false;

/**
 * Ensure BleClient is initialized exactly once per process lifetime.
 * `androidNeverForLocation: true` requests BLUETOOTH_SCAN without
 * ACCESS_FINE_LOCATION on Android 12+.
 */
async function ensureInitialized(): Promise<void> {
  if (initialized) return;
  await BleClient.initialize({ androidNeverForLocation: true });
  initialized = true;
}

/**
 * Parse the 8-byte peer-id from advertisement serviceData.
 * The native plugin encodes it as raw bytes in the serviceData field keyed
 * by MESH_SERVICE_UUID. BleClient already decodes it to a DataView.
 *
 * Returns null if serviceData is absent or malformed (not enough bytes).
 */
function parsePeerId(serviceData: { [key: string]: DataView } | undefined): Uint8Array | null {
  if (!serviceData) return null;

  // Key may be the full 128-bit UUID or the 16-bit short form; try both.
  const view =
    serviceData[MESH_SERVICE_UUID] ??
    serviceData[MESH_SERVICE_UUID.toUpperCase()] ??
    serviceData[MESH_SERVICE_UUID.toLowerCase()];

  if (!view || view.byteLength < PEER_ID_BYTES) return null;
  // B1.10: copy the bytes to avoid aliasing into the DataView's shared buffer,
  // which may be reused or mutated by the BLE plugin after the callback returns.
  return Uint8Array.from(new Uint8Array(view.buffer, view.byteOffset, PEER_ID_BYTES));
}

/**
 * Start BLE scan filtered to MESH_SERVICE_UUID.
 * Calls `onSighting` for every advertisement that carries a valid peer-id.
 * Advertisements without a parseable peer-id are silently discarded.
 */
export async function startScan(onSighting: (s: PeerSighting) => void): Promise<void> {
  await ensureInitialized();

  await BleClient.requestLEScan(
    {
      services: [MESH_SERVICE_UUID],
      allowDuplicates: true,
    },
    (result) => {
      const peerId = parsePeerId(result.serviceData);
      if (!peerId) return;

      onSighting({
        deviceId: result.device.deviceId,
        rssi: result.rssi ?? -999,
        peerId,
      });
    },
  );
}

/** Stop the active BLE scan. Safe to call even if no scan is running. */
export async function stopScan(): Promise<void> {
  await BleClient.stopLEScan();
}
