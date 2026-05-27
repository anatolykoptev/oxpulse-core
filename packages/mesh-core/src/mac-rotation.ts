export interface MacRotationOpts {
  intervalMs?: number;
  /** B1.11: if true, schedule first rotate via a random jitter in [0, intervalMs). Default true. */
  initialJitter?: boolean;
}

export class MacRotationTimer {
  private intervalMs: number;
  private rotate: () => void;
  private handle: ReturnType<typeof setInterval> | undefined;
  private jitterHandle: ReturnType<typeof setTimeout> | undefined;
  private paused = false;
  private initialJitter: boolean;

  constructor(rotate: () => void, opts: MacRotationOpts = {}) {
    this.rotate = rotate;
    this.intervalMs = opts.intervalMs ?? 15 * 60 * 1000;
    this.initialJitter = opts.initialJitter ?? true;
  }

  start(): void {
    if (this.handle !== undefined || this.jitterHandle !== undefined) throw new Error('already started');
    if (this.initialJitter) {
      // B1.11: stagger initial rotate to prevent a fleet of devices all
      // rotating at the same wall-clock moment.
      const delay = Math.random() * this.intervalMs;
      this.jitterHandle = setTimeout(() => {
        this.jitterHandle = undefined;
        if (!this.paused) this.rotate();
        // After jitter fires, start the regular interval.
        this.handle = setInterval(() => {
          if (!this.paused) this.rotate();
        }, this.intervalMs);
      }, delay);
    } else {
      this.handle = setInterval(() => {
        if (!this.paused) this.rotate();
      }, this.intervalMs);
    }
  }

  stop(): void {
    if (this.jitterHandle !== undefined) {
      clearTimeout(this.jitterHandle);
      this.jitterHandle = undefined;
    }
    if (this.handle !== undefined) {
      clearInterval(this.handle);
      this.handle = undefined;
    }
  }

  onVisibilityChange(visible: boolean): void {
    this.paused = !visible;
  }
}
