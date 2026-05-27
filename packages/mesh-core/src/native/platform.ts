import { Capacitor } from '@capacitor/core';

// UA-based fallback for contexts where the Capacitor runtime is not yet
// initialised (e.g. very early in boot before the WebView bridge fires).
const CAPACITOR_UA_MARK = 'OxPulseShell/1';

/**
 * Returns true when running inside the OxPulse Capacitor shell.
 * Primary detector: Capacitor.isNativePlatform() — authoritative at runtime.
 * Fallback: OxPulseShell/1 UA suffix injected by the WebView wrapper.
 */
export function isInCapacitor(ua = typeof navigator !== 'undefined' ? navigator.userAgent : ''): boolean {
  if (typeof Capacitor !== 'undefined' && Capacitor.isNativePlatform?.()) return true;
  return ua.includes(CAPACITOR_UA_MARK);
}

export function isAndroid(ua = typeof navigator !== 'undefined' ? navigator.userAgent : ''): boolean {
  if (typeof Capacitor !== 'undefined' && Capacitor.getPlatform?.() === 'android') return true;
  return isInCapacitor(ua) && /Android/i.test(ua);
}

export function isIOS(ua = typeof navigator !== 'undefined' ? navigator.userAgent : ''): boolean {
  if (typeof Capacitor !== 'undefined' && Capacitor.getPlatform?.() === 'ios') return true;
  return isInCapacitor(ua) && /iPhone|iPad|iPod/i.test(ua);
}

export function isNative(ua?: string): boolean {
  return isInCapacitor(ua);
}
