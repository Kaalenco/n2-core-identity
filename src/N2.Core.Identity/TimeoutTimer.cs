using System.Diagnostics;

namespace N2.Core.Identity;

internal sealed class TimeoutTimer {
    private readonly Stopwatch timer;
    private readonly int timeToWait;
    private readonly int step;

    public TimeoutTimer(int timeToWait) {
        this.timeToWait = timeToWait;
        this.step = timeToWait / 20;
        if (this.step > 1) {
            this.step = 1;
        }

        this.timer = new Stopwatch();
        this.timer.Start();
    }

    public async Task Wait() {
        if (timer.ElapsedMilliseconds > timeToWait) {
            return;
        }

        while (timer.ElapsedMilliseconds < timeToWait) {
            await Task.Delay(step);
        }
    }
}
