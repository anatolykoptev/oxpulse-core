import { describe, it, expect, vi } from 'vitest';
import { MacRotationTimer } from '../mac-rotation';

describe('MAC rotation', () => {
  it('fires rotate() every 15 minutes', () => {
    vi.useFakeTimers();
    const rotate = vi.fn();
    const t = new MacRotationTimer(rotate, { intervalMs: 900_000, initialJitter: false });
    t.start();
    vi.advanceTimersByTime(899_999);
    expect(rotate).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(rotate).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(900_000);
    expect(rotate).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });

  it('pauses on background, resumes on foreground', () => {
    vi.useFakeTimers();
    const rotate = vi.fn();
    const t = new MacRotationTimer(rotate, { intervalMs: 1000, initialJitter: false });
    t.start();
    t.onVisibilityChange(false);
    vi.advanceTimersByTime(5000);
    expect(rotate).not.toHaveBeenCalled();
    t.onVisibilityChange(true);
    vi.advanceTimersByTime(1000);
    expect(rotate).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });

  it('does not double-start', () => {
    const t = new MacRotationTimer(() => {}, { intervalMs: 1000, initialJitter: false });
    t.start();
    expect(() => t.start()).toThrow(/already/);
  });

  it('with initialJitter=false, rotate does not fire before intervalMs', () => {
    // B1.11: deterministic case — no jitter, behaves like plain setInterval
    vi.useFakeTimers();
    const rotate = vi.fn();
    const t = new MacRotationTimer(rotate, { intervalMs: 60_000, initialJitter: false });
    t.start();
    vi.advanceTimersByTime(59_999);
    expect(rotate).not.toHaveBeenCalled();
    t.stop();
    vi.useRealTimers();
  });

  it('with initialJitter=true, rotate fires once before intervalMs elapses', () => {
    // B1.11: jitter schedules first rotate via setTimeout in [0, intervalMs)
    vi.useFakeTimers();
    const rotate = vi.fn();
    const intervalMs = 60_000;
    const t = new MacRotationTimer(rotate, { intervalMs, initialJitter: true });
    t.start();
    // Advance to just under intervalMs — jitter fires somewhere in this window
    vi.advanceTimersByTime(intervalMs - 1);
    // Must have fired exactly once (the jittered initial call)
    expect(rotate).toHaveBeenCalledTimes(1);
    t.stop();
    vi.useRealTimers();
  });
});
