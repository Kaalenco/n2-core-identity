namespace N2.Core.Identity.Services;

internal sealed class Semafore
{
    private int count;
    private readonly object lockObject = new();

    public Semafore(int count)
    {
        this.count = count;
    }

    public void Release()
    {
        lock (lockObject)
        {
            count++;
            Monitor.Pulse(lockObject);
        }
    }

    public void Wait()
    {
        lock (lockObject)
        {
            while (count == 0)
            {
                Monitor.Wait(lockObject);
            }
            count--;
        }
    }
}