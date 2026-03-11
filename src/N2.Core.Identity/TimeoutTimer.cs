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
        var remaining = timeToWait - (int)timer.ElapsedMilliseconds;
        if (remaining > 0) {
            await Task.Delay(remaining);
        }
    }
}
