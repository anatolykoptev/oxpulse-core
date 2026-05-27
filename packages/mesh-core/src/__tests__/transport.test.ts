import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Hoist spy so it's available inside vi.mock factory (which is hoisted to top of file).
const { disconnectSpy } = vi.hoisted(() => ({
  disconnectSpy: vi.fn(async () => {}),
}));

// Mock the native plugin module BEFORE importing transport
vi.mock('@capacitor/core', () => ({
  registerPlugin: () => ({
    startAdvertising: vi.fn(async () => {}),
    stopAdvertising: vi.fn(async () => {}),
    startGattServer: vi.fn(async () => {}),
    stopGattServer: vi.fn(async () => {}),
    notifyTx: vi.fn(async () => {}),
    addListener: vi.fn(() => ({ remove: async () => {} })),
  }),
}));

vi.mock('@capacitor-community/bluetooth-le', () => ({
  BleClient: {
    initialize: vi.fn(async () => {}),
    requestLEScan: vi.fn(async () => {}),
    stopLEScan: vi.fn(async () => {}),
    connect: vi.fn(async () => {}),
    writeWithoutResponse: vi.fn(async () => {}),
    startNotifications: vi.fn(async () => {}),
    stopNotifications: vi.fn(async () => {}),
    discoverServices: vi.fn(async () => []),
    requestMtu: vi.fn(async () => 247),
    getMtu: vi.fn(async () => 247),
    disconnect: disconnectSpy,
  },
}));

import { startMesh, stopMesh, meshState, onFrame, sendFrame } from '../transport';
// Note: classifyMeshError is internal; we test it via meshState.error after startMesh throws.

describe('mesh transport', () => {
  beforeEach(() => {
    meshState.peers = [];
    meshState.advertising = false;
    meshState.scanning = false;
    meshState.error = null;
    disconnectSpy.mockClear();
  });

  afterEach(async () => {
    // Always stop to avoid test bleed-through
    if (meshState.advertising || meshState.scanning) {
      await stopMesh();
    }
  });

  it('starts advertising + scanning + gatt server', async () => {
    await startMesh();
    expect(meshState.advertising).toBe(true);
    expect(meshState.scanning).toBe(true);
  });

  it('stops cleanly', async () => {
    await startMesh();
    await stopMesh();
    expect(meshState.advertising).toBe(false);
    expect(meshState.scanning).toBe(false);
  });

  it('startMesh is idempotent — second call returns early', async () => {
    // B1.12: startMesh must be a no-op when already running
    await startMesh();
    const { BleClient } = await import('@capacitor-community/bluetooth-le');
    const callsBefore = (BleClient.requestLEScan as ReturnType<typeof vi.fn>).mock.calls.length;
    await startMesh(); // second call — must be no-op
    const callsAfter = (BleClient.requestLEScan as ReturnType<typeof vi.fn>).mock.calls.length;
    expect(callsAfter).toBe(callsBefore); // no new scan started
  });

  it('stopMesh calls disconnect for every connected peer', async () => {
    // B1.2: stopMesh must disconnect all connectedDevices
    // Simulate a peer being connected by driving the scan callback
    const { BleClient } = await import('@capacitor-community/bluetooth-le');
    const peerId = new Uint8Array(8).fill(0xab);
    const serviceData: Record<string, DataView> = {
      'f0f10000-6f78-7075-6c73-65000000c8b1': new DataView(peerId.buffer),
    };
    // Capture the scan callback so we can fire a sighting
    let scanCb: ((result: unknown) => void) | undefined;
    (BleClient.requestLEScan as ReturnType<typeof vi.fn>).mockImplementationOnce(
      async (_opts: unknown, cb: (result: unknown) => void) => { scanCb = cb; }
    );

    await startMesh();

    // Fire a sighting to trigger connect
    scanCb?.({ device: { deviceId: 'dev-aa:bb' }, rssi: -70, serviceData });
    // Allow microtasks to settle
    for (let i = 0; i < 20; i++) await Promise.resolve();

    await stopMesh();

    // disconnect must have been called for the connected peer
    expect(disconnectSpy).toHaveBeenCalledWith('dev-aa:bb');
  });

  // ── D2: error classification (meshState.error) ──────────────────────

  it('sets meshState.error = ble-off when startAdvertising rejects with BluetoothNotEnabled', async () => {
    // Simulate native plugin rejecting with a Bluetooth-disabled error.
    const { registerPlugin } = await import('@capacitor/core');
    // Re-mock the plugin for this test only — make startGattServer throw.
    // We reach startGattServer before startAdvertising in startAdvertising().
    // The easiest hook is to override the module-level MeshGatt mock for this call.
    const { BleClient } = await import('@capacitor-community/bluetooth-le');
    (BleClient.requestLEScan as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('BluetoothNotEnabled: BLE not enabled on this device'),
    );
    // startAdvertising (native) succeeds, but startScan will throw.
    // Re-mock MeshGatt.startGattServer to throw to test the ble-off path earlier.
    // Instead, test via a ble-scan failure that contains 'bluetooth' keyword.
    await expect(startMesh()).rejects.toThrow();
    // Classification must be set even when the error is thrown.
    // This path hits after startAdvertising succeeds but startScan throws.
    expect(meshState.error).toBe('ble-off');
  });

  it('sets meshState.error = permission-denied when startMesh rejects with permission error', async () => {
    const { BleClient } = await import('@capacitor-community/bluetooth-le');
    (BleClient.requestLEScan as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('missing-bluetooth-permission'),
    );
    await expect(startMesh()).rejects.toThrow();
    expect(meshState.error).toBe('permission-denied');
  });

  it('sets meshState.error = plugin-absent when startMesh rejects with not-implemented error', async () => {
    const { BleClient } = await import('@capacitor-community/bluetooth-le');
    (BleClient.requestLEScan as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('not implemented on this platform'),
    );
    await expect(startMesh()).rejects.toThrow();
    expect(meshState.error).toBe('plugin-absent');
  });

  it('sets meshState.error = unknown for unrecognised errors', async () => {
    const { BleClient } = await import('@capacitor-community/bluetooth-le');
    (BleClient.requestLEScan as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('unexpected internal failure'),
    );
    await expect(startMesh()).rejects.toThrow();
    expect(meshState.error).toBe('unknown');
  });

  it('clears meshState.error = null on successful startMesh', async () => {
    // Pre-seed an error to confirm it is cleared on success.
    meshState.error = 'ble-off';
    await startMesh();
    expect(meshState.error).toBeNull();
  });

  it('clears meshState.error = null on stopMesh', async () => {
    await startMesh();
    meshState.error = 'ble-off'; // simulate stale error
    await stopMesh();
    expect(meshState.error).toBeNull();
  });
});
