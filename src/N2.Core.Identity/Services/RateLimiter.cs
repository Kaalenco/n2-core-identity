using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace N2.Core.Identity.Services;

public interface IRateLimiter {
    void RecordAttempt(Guid reference, string? itemName, bool success);
    (bool Success, double RemainingTime) CheckRateLimit(Guid reference, string? itemName);
    void UpdateRateLimit(Guid reference, string? itemName, DateTime newEndDateTime);
}

public class RateLimiter : IRateLimiter {
    private readonly IMemoryCache memoryCache;
    private readonly ILogger logger;
    private readonly int maxAttemps;
    private readonly int lockoutMinutes;
    private readonly object lockObject = new();
    public RateLimiter(IMemoryCache memoryCache, ILogger logger, int maxAttempts, int lockoutMinutes) {
        this.memoryCache = memoryCache;
        this.logger = logger;
        this.maxAttemps = maxAttempts;
        this.lockoutMinutes = lockoutMinutes;
    }

    // Configuration from AuthenticationConfig
    private int MaxAttempts => maxAttemps > 0 ? maxAttemps : 5;
    private int LockoutMinutes => lockoutMinutes > 0 ? lockoutMinutes : 15;
    /// <summary>
    /// Gets or creates an MFA attempt tracker for an item.
    /// </summary>
    private RateLimitTracker GetOrCreateRateLimitTracker(Guid reference, string itemName) {
        var key = reference.ToString();
        var rateLimiter = memoryCache.Get<RateLimitTracker>(key);
        if (rateLimiter == null) {
            rateLimiter = new RateLimitTracker(reference, itemName, MaxAttempts, LockoutMinutes, logger);
            memoryCache.Set(key, rateLimiter, new MemoryCacheEntryOptions {
                SlidingExpiration = TimeSpan.FromMinutes(LockoutMinutes)
            });
        }

        return rateLimiter;
    }

    public void RecordAttempt(Guid reference, string? itemName, bool success) {
        lock (lockObject) {
            var limiter = GetOrCreateRateLimitTracker(reference, itemName ?? "unknown");
            limiter.RecordAttempt(success);
        }
    }
    public (bool Success, double RemainingTime) CheckRateLimit(Guid reference, string? itemName) {
        bool success;
        double remainingTime;
        lock (lockObject) {
            var limiter = GetOrCreateRateLimitTracker(reference, itemName ?? "unknown");
            (success, remainingTime) = limiter.CheckRateLimit();
        }
        return (success, remainingTime);
    }

    public void UpdateRateLimit(Guid reference, string? itemName, DateTime newEndDateTime) {
        var limiter = GetOrCreateRateLimitTracker(reference, itemName ?? "unknown");
        limiter.SetLockoutEnd(newEndDateTime);
    }
}
