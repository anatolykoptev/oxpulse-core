// Hand-written constants replaced by codegen — see mesh-constants.json.
// This file is kept as a stable import target; Step 3 (mesh-core move) will
// repoint importers directly to the generated package.
export * from './constants.generated.js';

/**
 * S7: Maximum concurrent BLE connections.
 * Android 4.4+: GATT_MAX_PHY_CHANNEL=7 (hard limit). iOS: 8-15 varies.
 * 6 gives a safety margin below Android's 7 to avoid error 133 hangs.
 */
export const MAX_BLE_CONNECTIONS = 6 as const;
