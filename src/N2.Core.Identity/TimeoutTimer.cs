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

    /// <summary>
    /// Waits until the configured time budget has elapsed since construction.
    /// </summary>
    /// <returns>
    /// <c>true</c> when the call had to pad (the work finished inside the budget); <c>false</c>
    /// when the budget was already used up, so the caller's timing was not equalised.
    /// </returns>
    public async Task<bool> Wait(CancellationToken ct) {
        if (timer.ElapsedMilliseconds >= timeToWait) {
            return false;
        }

        if (timeToWait < 20) {
            // For short timeouts yield-spin is more precise than Task.Delay,
            // which has ~15 ms system-timer resolution on Windows and can over-
            // or under-sleep by several milliseconds — unacceptable for the
            // constant-time comparisons that use a 10 ms target.
            while (timer.ElapsedMilliseconds < timeToWait) {
                ct.ThrowIfCancellationRequested();
                await Task.Yield();
            }
        } else {
            var remaining = timeToWait - (int)timer.ElapsedMilliseconds;
            if (remaining > 0) {
                await Task.Delay(remaining, ct);
            }
        }
        return true;
    }
}
