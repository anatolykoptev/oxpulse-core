import { describe, it, expect, vi } from 'vitest';

// Stub @capacitor/core so the module can be imported in a non-Capacitor
// test environment. isNativePlatform() returns false → UA path is exercised.
vi.mock('@capacitor/core', () => ({
  Capacitor: { isNativePlatform: () => false, getPlatform: () => 'web' },
}));

import { isNative, isAndroid, isInCapacitor, isIOS } from './platform.js';

describe('platform detection', () => {
  it('detects Capacitor via UA suffix', () => {
    const ua = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) ... OxPulseShell/1';
    expect(isInCapacitor(ua)).toBe(true);
    expect(isAndroid(ua)).toBe(true);
    expect(isNative(ua)).toBe(true);
  });

  it('returns false on plain browser', () => {
    const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/605';
    expect(isInCapacitor(ua)).toBe(false);
    expect(isNative(ua)).toBe(false);
  });

  // isIOS tests — Phase C
  it('isIOS: positive — iPhone UA with OxPulseShell/1 suffix', () => {
    const ua =
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 OxPulseShell/1';
    expect(isIOS(ua)).toBe(true);
  });

  it('isIOS: negative — plain web Safari (no shell suffix)', () => {
    const ua =
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1';
    expect(isIOS(ua)).toBe(false);
  });

  it('isIOS: negative — Android Capacitor shell is not iOS', () => {
    const ua = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537 OxPulseShell/1';
    expect(isIOS(ua)).toBe(false);
  });
});
