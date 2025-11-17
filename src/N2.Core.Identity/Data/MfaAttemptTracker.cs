namespace N2.Core.Identity.Data;

/// <summary>
/// Tracks MFA validation attempts for rate limiting and lockout.
/// </summary>
public class MfaAttemptTracker {
    public Guid UserId { get; set; }
    public int FailedAttempts { get; set; }
    public DateTime? LockoutUntil { get; set; }
    public DateTime LastAttempt { get; set; }
    public DateTime WindowStart { get; set; }

    /// <summary>
    /// Checks if the user is currently locked out from MFA attempts.
    /// </summary>
    public bool IsLockedOut => LockoutUntil.HasValue && LockoutUntil.Value > DateTime.UtcNow;

    /// <summary>
    /// Checks if the current attempt window has expired (15 minutes).
    /// </summary>
    public bool IsWindowExpired => (DateTime.UtcNow - WindowStart).TotalMinutes > 15;

    /// <summary>
    /// Resets the attempt counter and lockout status.
    /// </summary>
    public void Reset() {
        FailedAttempts = 0;
        LockoutUntil = null;
        WindowStart = DateTime.UtcNow;
        LastAttempt = DateTime.UtcNow;
    }

    /// <summary>
    /// Records a failed attempt and applies lockout if threshold exceeded.
    /// </summary>
    public void RecordFailure(int maxAttempts = 5, int lockoutMinutes = 15) {
        FailedAttempts++;
        LastAttempt = DateTime.UtcNow;

        if (FailedAttempts >= maxAttempts) {
            LockoutUntil = DateTime.UtcNow.AddMinutes(lockoutMinutes);
        }
    }
}