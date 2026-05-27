import { registerPlugin } from '@capacitor/core';
import type { PluginListenerHandle } from '@capacitor/core';

/**
 * TS interface mirroring MeshGattServerPlugin.kt public contract (Task 7, 907360b0).
 * peerId is 16 hex chars (8 bytes).
 */
export interface MeshGattServerPlugin {
  startAdvertising(options: { peerId: string }): Promise<void>;
  stopAdvertising(): Promise<void>;
  startGattServer(): Promise<void>;
  stopGattServer(): Promise<void>;
  notifyTx(options: { deviceAddress: string; data: string }): Promise<void>;
  addListener(
    eventName: string,
    listenerFunc: (...args: unknown[]) => void,
  ): Promise<PluginListenerHandle>;
  /** Open system Bluetooth settings (Android only). */
  openBluetoothSettings(): Promise<void>;
  /** Open per-app permission settings (Android only). */
  openAppPermissionSettings(): Promise<void>;
}

/**
 * Open the Android system Bluetooth settings screen.
 * No-op on platforms where the plugin is absent.
 */
export async function openBluetoothSettings(): Promise<void> {
  await MeshGatt.openBluetoothSettings();
}

/**
 * Open the Android per-app permission settings screen.
 * No-op on platforms where the plugin is absent.
 */
export async function openAppPermissionSettings(): Promise<void> {
  await MeshGatt.openAppPermissionSettings();
}

/** Bound instance of the native MeshGattServer Capacitor plugin. */
export const MeshGatt = registerPlugin<MeshGattServerPlugin>('MeshGattServer');

/**
 * Begin BLE advertising + open the GATT server so remote peers can discover
 * and connect to us.
 *
 * @param peerId 8-byte ephemeral peer identifier. Encoded as 16 lowercase hex
 *   chars and passed to the Kotlin plugin as serviceData in the advertisement.
 */
export async function startAdvertising(peerId: Uint8Array): Promise<void> {
  if (peerId.byteLength !== 8) {
    throw new Error(`startAdvertising: peerId must be 8 bytes, got ${peerId.byteLength}`);
  }
  const hex = Array.from(peerId)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  await MeshGatt.startGattServer();
  await MeshGatt.startAdvertising({ peerId: hex });
}

/** Stop advertising and close the GATT server. */
export async function stopAdvertising(): Promise<void> {
  await MeshGatt.stopAdvertising();
  await MeshGatt.stopGattServer();
}
