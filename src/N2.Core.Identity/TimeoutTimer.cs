using System.Diagnostics;

namespace N2.Core.Identity;

internal sealed class TimeoutTimer {
    private readonly Stopwatch timer;
    private readonly int timeToWait;

    public TimeoutTimer(int timeToWait) {
        this.timeToWait = timeToWait;
        this.timer = new Stopwatch();
        this.timer.Start();
    }

    public async Task Wait() {
        if (timer.ElapsedMilliseconds >= timeToWait) {
            return;
        }

        if (timeToWait < 20) {
            // For short timeouts yield-spin is more precise than Task.Delay,
            // which has ~15 ms system-timer resolution on Windows and can over-
            // or under-sleep by several milliseconds — unacceptable for the
            // constant-time comparisons that use a 10 ms target.
            while (timer.ElapsedMilliseconds < timeToWait) {
                await Task.Yield();
            }
        } else {
            var remaining = timeToWait - (int)timer.ElapsedMilliseconds;
            if (remaining > 0) {
                await Task.Delay(remaining);
            }
        }
    }
}
