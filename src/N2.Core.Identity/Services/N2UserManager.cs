using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Models;

using OtpNet;

using QRCoder;

using System.Data;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Mail;
using System.Security.Cryptography;

namespace N2.Core.Identity.Services;

#pragma warning disable CA1725
// Using ct and not token for CancellationToken parameter names in async methods is
// a common convention in .NET, and it is more concise. The CA1725 warning is not relevant in this context.

public sealed class N2UserManager : IN2UserManager, IHaveSecrets {

    /// <summary>
    /// A divisor for converting ticks to seconds
    /// </summary>
    private const long TicksToSeconds = 10000000L;

    // This is the amount of time we want to take for the authentication process, regardless of success or failure,
    // to mitigate timing attacks for user enumeration and password guessing.
    // It should not be too long to cause a poor user experience, but long enough to make brute-force attacks less feasible.
    // 500ms is a common choice for this kind of delay, but it can be adjusted based on the expected load
    // and security requirements of the application. A value of 200 is too short and may not provide sufficient protection,
    // while a value of 1000 may be unnecessarily long for users with valid credentials.
    private const int TimeForAuthenticationMs = 500;

    /// <summary>
    /// The number of ticks as Measured at Midnight Jan 1st 1970;
    /// </summary>
    private const long UnicEpocTicks = 621355968000000000L;

    private static readonly Action<ILogger, Guid, Exception?> _logRotateMfaSecretDecryptionFailed =
        LoggerMessage.Define<Guid>(
            LogLevel.Warning,
            new EventId(1001, nameof(RotateMfaSecrets)),
            "RotateMfaSecrets: could not decrypt MfaSecret for user {UserId} — skipping.");

    private static readonly Action<ILogger, int, Exception?> _logRotateMfaSecretRotated =
        LoggerMessage.Define<int>(
            LogLevel.Information,
            new EventId(1002, nameof(RotateMfaSecrets)),
            "\"RotateMfaSecrets: re-encrypted {Count} MfaSecret(s).\"");

    private static readonly MultiFactorType[] allowedConfirmation = [MultiFactorType.Email, MultiFactorType.Sms];
    private readonly AuthenticationConfig configuration;

    private readonly DatabaseProvider provider;

    /// <summary>
    /// Gets the name of the database connection used for establishing connections.
    /// </summary>
    private readonly string connectionName;
    private readonly IIdentityContextFactory factory;
    private readonly ILogger<N2UserManager> logger;
    private readonly IChangeLogWriter? changeLogWriter;
    private readonly IVaultCallerContext? callerContext;

    // Intentionally not disposed: Dispose() may be called by the DI container while
    // ValidateMultifactor is still waiting on WaitAsync(), which would cause an
    // ObjectDisposedException. SemaphoreSlim has no unmanaged resources; the GC reclaims it.
#pragma warning disable CA2213
    private readonly SemaphoreSlim lockObject = new(1, 1);
#pragma warning restore CA2213

    private readonly IPasswordHasher<ApplicationUser> passwordHasher;
    private readonly IRateLimiter rateLimiter;

#pragma warning disable CA2213 // Disposable fields should be disposed
    private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
#pragma warning restore CA2213 // Disposable fields should be disposed

    private bool disposedValue;

    public bool SupportsUserEmail { get; }

    public N2UserManager(
        IIdentityContextFactory identityContextFactory,
        IConfiguration configuration,
        IRateLimiter rateLimiter,
        IPasswordHasher<ApplicationUser> passwordHasher,
        string connectionName,
        ILogger<N2UserManager> logger,
        DatabaseProvider provider = DatabaseProvider.SqlServer,
        IChangeLogWriter? changeLogWriter = null,
        IVaultCallerContext? callerContext = null) {
        this.factory = identityContextFactory;
        this.connectionName = connectionName;
        this.provider = provider;
        this.logger = logger;
        this.rateLimiter = rateLimiter;
        this.passwordHasher = passwordHasher;
        this.changeLogWriter = changeLogWriter;
        this.callerContext = callerContext;

        this.configuration = configuration.GetAuthenticationConfig();

        // Validate token signing secret
        if (string.IsNullOrEmpty(this.configuration.TokenSigningSecret)) {
            throw new InvalidOperationException(
                "TokenSigningSecret is required in Authentication configuration. " +
                "Generate a secure key using: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))"
            );
        }

        var secretBytes = Convert.FromBase64String(this.configuration.TokenSigningSecret);
        if (secretBytes.Length < 32) {
            throw new InvalidOperationException(
                $"TokenSigningSecret must be at least 32 bytes (256 bits). Current length: {secretBytes.Length} bytes"
            );
        }
    }

    /// <summary>Stores a user alert.</summary>
    /// <returns>The persistence status from <see cref="N2.Core.Entity.IUnitOfWork.Complete(CancellationToken)"/>.</returns>
    public async Task<ResponseStatus> CreateUserAlert(Guid userId, UserAlert userAlert, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(userAlert);
        using var ctx = await CreateContext(ct);
        var alert = new ApplicationUserAlert {
            ApplicationUserId = userId,
            Message = userAlert.Message,
            Priority = userAlert.Priority,
            CreatedAt = DateTime.UtcNow
        };
        await ctx.UserAlertAdd(alert, ct);
        var (status, _) = await ctx.Complete(ct);
        return status;
    }

    /// <summary>
    /// Returns all tenant memberships for the given user in a single query,
    /// including the roles the user holds within each tenant.
    /// Today the only tenant-scoped role is <see cref="SystemRoles.Admin"/>, derived from
    /// <see cref="ApplicationUserTenant.IsAdmin"/>. The structure supports additional per-tenant
    /// roles once a dedicated role table is introduced.
    /// </summary>
    public async Task<IList<(Guid TenantId, string TenantName, IReadOnlyList<string> Roles)>> GetTenantMemberships(
        ApplicationUser user,
        CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);

        using var ctx = await CreateContext(ct);

        var rows = await ctx.UserTenant
            .AsNoTracking()
            .Where(ut => ut.ApplicationUserId == user.Id)
            .Select(ut => new {
                ut.ApplicationTenantId,
                TenantName = ut.ApplicationTenant.Name ?? string.Empty,
                ut.IsAdmin
            })
            .ToListAsync(ct);

        return rows
            .Select(r => (
                r.ApplicationTenantId,
                r.TenantName,
                (IReadOnlyList<string>)(r.IsAdmin ? [SystemRoles.Admin] : [])))
            .ToList();
    }

    public async Task<ICommandResponse> AddToRole(ApplicationUser user, string role, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContext(ct);
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.RoleFindRecord(normalizedName, ct);
        if (roleItem == null) {
            return new RequestResult(ResponseStatus.NotAcceptable, $"Role '{role}' does not exist");
        }
        var isAssigned = await ctx.UserRoleFindRecord(user.Id, roleItem.Id, ct);
        if (isAssigned != null) {
            return RequestResult.Ok();
        }
        IdentityUserRole<Guid> userRole = new() {
            RoleId = roleItem.Id,
            UserId = user.Id
        };
        await ctx.UserRoleAdd(userRole, ct);
        (var code, var message) = await ctx.Complete(ct);
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<bool> ApplicationUserCanSignIn([NotNull] ApplicationUser user, CancellationToken ct) {
        using var ctx = await CreateContext(ct);
        return await ctx.UserCanSignIn(user.Id, ct);
    }

    Task<bool> IUserManager<ApplicationUser>.CanSignIn(ApplicationUser user, CancellationToken ct)
        => ApplicationUserCanSignIn(user, ct);

    public async Task<ICommandResponse> ConfirmEmail([NotNull] ApplicationUser user, string confirmationToken, CancellationToken ct) {
        using var ctx = await CreateContext(ct);
        var (flowControl, value, dbUser) = await ValidateConfirmationToken(ctx, user.Id, user.UserName, MultiFactorType.Email, user.Email, confirmationToken, ct);
        if (!flowControl) {
            return value;
        }

        // dbUser should be set
        dbUser!.LockoutEnabled = true;
        dbUser!.EmailConfirmed = true;
        (var code, var message) = await ctx.Complete(ct);
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> Create([NotNull] ApplicationUser user, string password, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(password);

        using var ctx = await CreateContext(ct);
        var dbUser = await ApplicationUserByName(ctx, user.UserName ?? string.Empty, ct);
        if (dbUser != null) {
            return new RequestResult(406, "Already exists");
        }

        ArgumentException.ThrowIfNullOrEmpty(user.UserName);
        ArgumentException.ThrowIfNullOrEmpty(user.Email);

        var randomBytes = RandomNumberGenerator.GetBytes(32);
        var secret = Convert.ToBase64String(randomBytes);
        user.NormalizedUserName = user.UserName.Trim().ToUpperInvariant();
        user.NormalizedEmail = user.Email.Trim().ToUpperInvariant();
        user.EmailConfirmed = false;
        user.MfaSecret = MfaSecretEncryption.Encrypt(secret, configuration.MfaTokenSecret);
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        user.PasswordHash = passwordHasher.HashPassword(user, password);
        await ctx.UserAdd(user, ct);
        (var code, var message) = await ctx.Complete(ct);
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> CreateRole(string role, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContext(ct);
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.RoleFindRecord(normalizedName, ct);
        if (roleItem != null) {
            return new RequestResult(406, "Already exists");
        }
        roleItem = new ApplicationRole {
            Name = role,
            NormalizedName = normalizedName
        };
        await ctx.RoleAdd(roleItem, ct);

        (var code, var message) = await ctx.Complete(ct);
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> Delete([NotNull] ApplicationUser user, CancellationToken ct) {
        using var ctx = await CreateContext(ct);
        ctx.UserDelete(user);
        (var code, var message) = await ctx.Complete(ct);
        return new RequestResult(code, message ?? string.Empty);
    }

    public void Dispose() {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByEmail(string emailAddress, CancellationToken ct) {
        using var ctx = await CreateContext(ct);
        var result = await ApplicationUserFindRecordByEmail(ctx, emailAddress, ct);
        return new ApplicationUserResponse(result);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindById(Guid userId, CancellationToken ct) {
        using var ctx = await CreateContext(ct);
        var user = await ApplicationUserById(ctx, userId, ct);
        return new ApplicationUserResponse(user);
    }

    public async Task<ICommandResponse<ApplicationUser>> ApplicationUserFind(string? userName, CancellationToken ct) {
        using var ctx = await CreateContext(ct);
        var user = await ApplicationUserByName(ctx, userName, ct);
        return new ApplicationUserResponse(user);
    }

    Task<ICommandResponse<ApplicationUser>> IUserManager<ApplicationUser>.FindByName(string userName, CancellationToken ct)
        => ApplicationUserFind(userName, ct);

    public async Task<ICommandResponse<string>> GenerateConfirmationToken([NotNull] ApplicationUser user, CancellationToken ct) {

        using var ctx = await CreateContext(ct);
        var mfaType = user.MfaType;
        ApplicationUser? dbUser;
        if (user.Id == Guid.Empty) {
            dbUser = await ApplicationUserByName(ctx, user.UserName, ct);

        } else {
            dbUser = await ApplicationUserById(ctx, user.Id, ct);
        }
        if (dbUser == null) {
            throw new InvalidOperationException("Invalid user");
        }

        if (mfaType == MultiFactorType.None) {
            dbUser.MfaSecret = string.Empty;
            dbUser.MfaType = mfaType;
            await ctx.Complete(ct);
            return StringResponse.Accept(string.Empty);
        }

        var randomBytes = RandomNumberGenerator.GetBytes(32);
        var secret = Convert.ToBase64String(randomBytes);

        dbUser.MfaSecret = MfaSecretEncryption.Encrypt(secret, configuration.MfaTokenSecret);
        dbUser.MfaType = mfaType;
        await ctx.Complete(ct);

        if (mfaType == MultiFactorType.Totp) {

            Totp otp = new(Convert.FromBase64String(secret)); // use plaintext — already in scope
            var validCode = otp.ComputeTotp(DateTime.UtcNow);
            return string.IsNullOrEmpty(validCode)
                ? StringResponse.Fail(string.Empty, "Could not generate a valid OTP code.")
                : StringResponse.Accept(validCode);
        }
        if (mfaType == MultiFactorType.Email || mfaType == MultiFactorType.Sms) {
            var nonceBytes = RandomNumberGenerator.GetBytes(32); // 256 bits
            var nonce = Convert.ToBase64String(nonceBytes);
            var timeOut = DateTime.UtcNow.AddDays(5).Ticks;

            var message = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}:{dbUser.SecurityStamp}");
            var keyBytes = Convert.FromBase64String(configuration.TokenSigningSecret);

            using var hmac = new HMACSHA256(keyBytes);
            var signature = hmac.ComputeHash(message);

            var data = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}");
            var result = string.Concat(Convert.ToBase64String(data), '.', Convert.ToBase64String(signature));
            return StringResponse.Accept(result);
        }
        return StringResponse.Fail(string.Empty, $"Not supported: {user.MfaType}");
    }

    public async Task<IListResponse<string>> GetRoles([NotNull] ApplicationUser user, CancellationToken ct) {
        using var ctx = await CreateContext(ct);
        var roles = await ctx.UserGetRoles(user.Id, ct);
        ListResponse<string> response = new(roles);
        return response;
    }

    public async Task<ICommandResponse<Guid>> GetUserId(ApplicationUser user, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);
        using var ctx = await CreateContext(ct);
        var normalizedName = (user.UserName ?? "").Trim().ToUpperInvariant();
        var userRecord = await ctx.User.FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedName, ct);
        var result = userRecord?.Id ?? Guid.Empty;
        return GuidResponse.Accept(result);
    }

    public async Task<ICommandResponse> IsInRole(ApplicationUser user, string role, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContext(ct);
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.RoleFindRecord(normalizedName, ct);
        if (roleItem == null) {
            return new GuidResponse(Guid.Empty, (int)ResponseStatus.NotFound, $"Role not found: {role}");
        }
        var isAssigned = await ctx.UserRoleFindRecord(user.Id, roleItem.Id, ct);
        if (isAssigned != null) {
            return new GuidResponse(roleItem.Id, (int)ResponseStatus.Success, role);
        } else {
            return new GuidResponse(roleItem.Id, (int)ResponseStatus.NotAccepted, role);
        }
    }

    public async Task<ICommandResponse> RemoveFromRole(ApplicationUser user, string role, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContext(ct);
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.RoleFindRecord(normalizedName, ct);
        if (roleItem == null) {
            return new RequestResult(406, $"Role '{role}' does not exist");
        }
        var isAssigned = await ctx.UserRoleFindRecord(user.Id, roleItem.Id, ct);
        if (isAssigned == null) {
            return RequestResult.Ok();
        }
        ctx.UserRoleDelete(isAssigned);
        (var code, var message) = await ctx.Complete(ct);
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> RemoveRole(string role, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContext(ct);
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.Role.FirstOrDefaultAsync(r => r.NormalizedName == normalizedName, ct);
        if (roleItem == null) {
            return RequestResult.NotFound();
        }
        ctx.RoleDelete(roleItem);
        (var code, var message) = await ctx.Complete(ct);
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<bool> RoleExists(string role, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContext(ct);
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleId = await ctx.RoleFindRecord(normalizedName, ct);
        return roleId != null;
    }

    /// <summary>
    /// Attempts to re-encrypt a single user's MFA secret with the primary key.
    /// </summary>
    /// <param name="user">The user whose <c>MfaSecret</c> should be rotated.</param>
    /// <returns>
    /// <see langword="true"/> if the secret was re-encrypted with the primary key;
    /// <see langword="false"/> if it was already current, or decryption failed (warning is logged).
    /// </returns>
    private bool TryRotateUserMfaSecret(ApplicationUser user) {
        // Try the secondary (retiring) key exclusively first. If decryption succeeds here,
        // the secret was encrypted with the old key and must be rotated.
        // If it fails, the secret is either already on the primary key or is unreadable.
        var plaintext = MfaSecretEncryption.TryDecrypt(
            user.MfaSecret,
            primaryBase64Key: configuration.MfaTokenSecret2,
            secondaryBase64Key: null);

        if (plaintext == null) {
            // Could not decrypt with secondary key — verify it is readable with the primary key.
            var verify = MfaSecretEncryption.TryDecrypt(
                user.MfaSecret,
                primaryBase64Key: configuration.MfaTokenSecret,
                secondaryBase64Key: null);

            if (verify == null) {
                // Neither key works — log and skip.
                _logRotateMfaSecretDecryptionFailed(logger, user.Id, null);
            }

            // Already encrypted with primary key (or unreadable) — no change needed.
            return false;
        }

        // Secret was encrypted with the retiring key — re-encrypt with the primary key.
        user.MfaSecret = MfaSecretEncryption.Encrypt(plaintext, configuration.MfaTokenSecret);
        return true;
    }

    /// <summary>
    /// Re-encrypts all <c>MfaSecret</c> values from <c>MfaTokenSecret2</c> (the retiring key)
    /// to <c>MfaTokenSecret</c> (the new primary key).
    /// </summary>
    /// <remarks>
    /// Key rotation workflow:
    /// <list type="number">
    ///   <item>Set <c>MfaTokenSecret2</c> to the current value of <c>MfaTokenSecret</c>.</item>
    ///   <item>Set <c>MfaTokenSecret</c> to the new key.</item>
    ///   <item>Deploy the updated configuration.</item>
    ///   <item>Call this method once to re-encrypt all rows.</item>
    ///   <item>Clear <c>MfaTokenSecret2</c> after the method completes successfully.</item>
    /// </list>
    /// </remarks>
    /// <returns>The number of rows re-encrypted.</returns>
    public async Task<int> RotateMfaSecrets(CancellationToken ct) {
        if (string.IsNullOrEmpty(configuration.MfaTokenSecret2)) {
            throw new InvalidOperationException(
                "MfaTokenSecret2 must contain the retiring key before rotation can proceed.");
        }

        using var ctx = await CreateContext(ct);

        // Using explicit null / empty check because string.IsNullOrEmpty is not translatable
        // to SQL and would pull all rows into memory before filtering.
        var users = await ctx.User
            .Where(u => u.MfaSecret != null && u.MfaSecret != string.Empty)
            .ToListAsync(ct);

        var rotated = users.Count(TryRotateUserMfaSecret);

        if (rotated > 0) {
            await ctx.Complete(ct);
            _logRotateMfaSecretRotated(logger, rotated, null);
        }

        return rotated;
    }

    public async Task<ICommandResponse> SetEmail([NotNull] ApplicationUser user, string email, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(email);
        (var emailValid, var message) = ValidateEmail(email);
        if (!emailValid) {
            return new RequestResult(406, message);
        }
        using var ctx = await CreateContext(ct);
        var dbUser = await ApplicationUserByName(ctx, user.UserName ?? string.Empty, ct);
        if (dbUser != null && dbUser.Id != user.Id) {
            return new RequestResult(406, "Already occupied");
        }
        user.Email = email.Trim();
        user.NormalizedEmail = email.Trim().ToUpperInvariant();
        user.EmailConfirmed = false;
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        (var status, var commitMessage) = await ctx.Complete(ct);
        return status.IsSuccess()
            ? RequestResult.Ok()
            : new RequestResult(status, $"Email not set for {user.Id}, {commitMessage}");
    }

    public async Task<ICommandResponse<MultiFactorProperties>> SetMultifactor(
        ApplicationUser user,
        MultiFactorType mfaType,
        string mfaToken,
        CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(mfaToken);

        if (string.IsNullOrEmpty(user.UserName)) {
            return MultifactorResponse.Failed("User name is not valid.");
        }

        byte[]? qrCode = null;
        var userUri = string.Empty;

        var code = new byte[20]; // 160 bits — meets NIST SP 800-63B Section 5.1.5 minimum
        rng.GetBytes(code);
        var rngCode = Convert.ToBase64String(code);

        switch (mfaType) {
            case MultiFactorType.None:
                break;

            case MultiFactorType.Sms:
                userUri = $"phone://{user.PhoneNumber}";
                break;

            case MultiFactorType.Email:
                userUri = $"mailto://{user.Email}?subject=ValidationCode";
                break;

            case MultiFactorType.Totp:

                // The otpauth://totp/ spec requires the secret to be Base32 (RFC 4648).
                // rngCode is Base64 (kept as-is for encrypted storage and server-side
                // verification via TryConvertBase64String); the URI gets a separate
                // Base32 encoding of the same raw bytes so authenticator apps can parse it.
                var base32Secret = Base32Encoding.ToString(code);
                userUri = GenerateQrCodeUri(user.UserName, base32Secret, configuration.TwoFactorTotpName);
                qrCode = GenerateQrCode(userUri);
                break;

            default:
                return MultifactorResponse.Failed($"Not supported : {mfaType}.");
        }

        using var ctx = await CreateContext(ct);
        var dbUser = await ApplicationUserByName(ctx, user.UserName, ct);
        if (dbUser is null) {
            return new MultifactorResponse(ResponseStatus.NotFound, $"Could not find user {user.UserName}");
        }
        dbUser.MfaSecret = MfaSecretEncryption.Encrypt(rngCode, configuration.MfaTokenSecret);
        dbUser.MfaType = mfaType;
        (var responseCode, var message) = await ctx.Complete(ct);

        if (responseCode.IsSuccess()) {
            MultiFactorProperties result = new() {
                MultiFactorType = mfaType,
                QrCode = qrCode,
                Uri = new Uri(userUri)
            };
            return new MultifactorResponse(responseCode, result);
        } else {
            return new MultifactorResponse(responseCode, message ?? "");
        }
    }

    public async Task<ICommandResponse> SetUserName([NotNull] ApplicationUser user, string userName, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(userName);
        using var ctx = await CreateContext(ct);
        var dbUser = await ApplicationUserByName(ctx, userName, ct);
        if (dbUser != null && dbUser.Id != user.Id) {
            return new RequestResult(406, "Already occupied");
        }
        user.UserName = userName.Trim();
        user.NormalizedUserName = userName.Trim().ToUpperInvariant();
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        (var status, var commitMessage) = await ctx.Complete(ct);
        return status.IsSuccess()
            ? RequestResult.Ok()
            : new RequestResult(status, $"Username not set for {user.Id}, {commitMessage}");
    }

    public void UpdateRateLimiter(Guid userId, string? userName, DateTime newEndDate) {
        rateLimiter.UpdateRateLimit(userId, userName, newEndDate);
    }

    public async Task<ICommandResponse> Validate(ApplicationUser user, string password, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(password);
        var timer = new TimeoutTimer(TimeForAuthenticationMs);

        using var ctx = await CreateContext(ct);
        var normalizedUserName = user.UserName?.ToUpperInvariant() ?? string.Empty;
        var appUser = await ctx.User
            .Where(m => m.NormalizedUserName == normalizedUserName)
            .FirstOrDefaultAsync(ct);

        if (appUser == null) {
            await timer.Wait(ct);
            return new RequestResult(ResponseStatus.NotAccepted, "Not accepted");
        }

        // Lockout check on the DB record — never on the caller-supplied object, which may be stale.
        if (IsLockedOut(appUser)) {
            var lockoutEnd = appUser.LockoutEnd!.Value;
            var remainingTime = lockoutEnd - DateTimeOffset.UtcNow;
            logger.LogUserLockedOut(appUser.UserName ?? appUser.Id.ToString(), lockoutEnd, Math.Ceiling(remainingTime.TotalMinutes));
            await timer.Wait(ct);
            return new RequestResult(423, $"Account is locked. Try again after {lockoutEnd:u}");
        }

        var verificationResult = passwordHasher.VerifyHashedPassword(
            appUser,
            appUser.PasswordHash ?? "",
            password
        );

        if (verificationResult == PasswordVerificationResult.Failed) {
            // Record the failed attempt before the cancellable padding wait, so cancelling the
            // request cannot skip the lockout counter. The padding makes this path take the same
            // time as the unknown-user and locked-out paths (no user enumeration by timing).
            _ = ReportCounterStatus(appUser.Id, await IncrementAccessFailedCount(ctx, appUser, logger));
            await timer.Wait(ct);
            return new RequestResult(ResponseStatus.NotAccepted, "Not accepted");
        }

        // Password verified successfully - reset failed count
        _ = ReportCounterStatus(appUser.Id, await ResetAccessFailedCount(ctx, appUser));

        // Optional: Rehash if using outdated format
        if (verificationResult == PasswordVerificationResult.SuccessRehashNeeded) {
            appUser.PasswordHash = passwordHasher.HashPassword(appUser, password);
            await ctx.Complete(ct);
        }
        return new RequestResult(ResponseStatus.Success, user.UserName ?? string.Empty);
    }

    /// <summary>
    /// Logs when a lockout counter write was not persisted.
    /// </summary>
    /// <returns><c>true</c> when <paramref name="status"/> is a success status.</returns>
    private bool ReportCounterStatus(Guid userId, ResponseStatus status) {
        if (status.IsSuccess()) {
            return true;
        }
        logger.LogAccessFailedCountNotPersisted(userId, status);
        return false;
    }
    public async Task<ICommandResponse> ValidateMultifactor(ApplicationUser user, string multifactorCode, CancellationToken ct) {

        ArgumentNullException.ThrowIfNull(user);
        var timer = new TimeoutTimer(TimeForAuthenticationMs);
        await lockObject.WaitAsync(ct);
        try {
            // Check rate limiting FIRST (before any validation)
            var (rateLimitCheck, remainingTime) = rateLimiter.CheckRateLimit(user.Id, user.NormalizedUserName);
            if (!rateLimitCheck) {
                await timer.Wait(ct);
                return new MultifactorResponse(
                    ResponseStatus.Unauthorized,
                    $"Too many failed MFA attempts. Account locked for {remainingTime} more minutes."
                );
            }

            using var ctx = await CreateContext(ct);

            if (string.IsNullOrEmpty(user.UserName)) {
                await timer.Wait(ct);
                return MultifactorResponse.Failed("User name is not valid.");
            }

            var dbUser = await ApplicationUserByName(ctx, user.UserName, ct);
            if (dbUser is null) {
                return await RejectMultifactor(user, timer, $"Could not find user {user.UserName}", ct);
            }
            if (dbUser.MfaType == MultiFactorType.None) {
                await timer.Wait(ct);
                return new MultifactorResponse(ResponseStatus.Accepted, "No multifactor required.");
            }

            return await VerifyMultifactorCode(user, dbUser, multifactorCode, timer, ct);
        } finally {
            lockObject.Release();
        }
    }

    /// <summary>
    /// Records a failed MFA attempt, then waits out the constant-time budget.
    /// </summary>
    /// <remarks>
    /// The attempt is recorded before the cancellable padding wait, so cancelling the request
    /// cannot skip the rate-limiter record.
    /// </remarks>
    private async Task<ICommandResponse> RejectMultifactor(ApplicationUser user, TimeoutTimer timer, string message, CancellationToken ct) {
        rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
        await timer.Wait(ct);
        return new MultifactorResponse(ResponseStatus.Unauthorized, message);
    }

    /// <summary>
    /// Verifies <paramref name="multifactorCode"/> for a user whose MFA type is not None.
    /// </summary>
    private async Task<ICommandResponse> VerifyMultifactorCode(
        ApplicationUser user,
        ApplicationUser dbUser,
        string multifactorCode,
        TimeoutTimer timer,
        CancellationToken ct) {
        string[] splitCode = [];
        if (dbUser.MfaType == MultiFactorType.Email) {
            var formatError = SplitEmailCode(multifactorCode, out splitCode);
            if (formatError != null) {
                return await RejectMultifactor(user, timer, formatError, ct);
            }
        }

        if (string.IsNullOrEmpty(user.MfaSecret)) {
            logger.LogMfaSecretNotSet(user.UserName ?? string.Empty);
            await timer.Wait(ct);
            return new MultifactorResponse(ResponseStatus.Conflict, "Multifactor is not configured.");
        }

        if (dbUser.MfaType == MultiFactorType.Totp) {
            return await VerifyTotpCode(user, dbUser, multifactorCode, timer, ct);
        }
        if (dbUser.MfaType is MultiFactorType.Sms or MultiFactorType.Email) {
            return await VerifySignedCode(user, dbUser, splitCode, timer, ct);
        }

        // Record before the cancellable padding wait so cancelling cannot skip the record.
        rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
        await timer.Wait(ct);
        return new MultifactorResponse(
            ResponseStatus.NotImplemented,
            $"Multifactor {user.MfaType} is not available for {user.UserName}");
    }

    /// <summary>
    /// Splits an e-mail MFA code into its two dot-separated parts.
    /// </summary>
    /// <returns>An error message when the code is missing or malformed; otherwise <c>null</c>.</returns>
    private static string? SplitEmailCode(string multifactorCode, out string[] splitCode) {
        splitCode = [];
        if (string.IsNullOrEmpty(multifactorCode) || !multifactorCode.Contains('.', StringComparison.Ordinal)) {
            return "No multifactor code provided.";
        }
        splitCode = multifactorCode.Split('.');
        return splitCode.Length == 2 ? null : "Invalid token format";
    }

    /// <summary>
    /// Verifies a TOTP code against the user's decrypted MFA secret.
    /// </summary>
    private async Task<ICommandResponse> VerifyTotpCode(
        ApplicationUser user,
        ApplicationUser dbUser,
        string multifactorCode,
        TimeoutTimer timer,
        CancellationToken ct) {
        var decryptedSecret = MfaSecretEncryption.TryDecrypt(dbUser.MfaSecret, configuration.MfaTokenSecret, configuration.MfaTokenSecret2);
        var (verified, message) = VerifyTwoFactorAuthentication(multifactorCode, decryptedSecret ?? "");
        // Record before the cancellable padding wait so cancelling cannot skip the record.
        rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, verified);
        await timer.Wait(ct);

        return verified
            ? MultifactorResponse.Ok()
            : new MultifactorResponse(ResponseStatus.Unauthorized, message);
    }

    /// <summary>
    /// Verifies an SMS or e-mail code: <c>{base64(nonce:expiryTicks)}.{base64(hmac)}</c>.
    /// </summary>
    private async Task<ICommandResponse> VerifySignedCode(
        ApplicationUser user,
        ApplicationUser dbUser,
        string[] splitCode,
        TimeoutTimer timer,
        CancellationToken ct) {
#pragma warning disable CA1031 // Do not catch general exception types
        try {
            var publicPart = Convert.FromBase64String(splitCode[0]);
            var publicTestPart = System.Text.Encoding.UTF8.GetString(publicPart).Split(':', StringSplitOptions.RemoveEmptyEntries);

            if (publicTestPart.Length != 2) {
                return await RejectMultifactor(user, timer, "Invalid token structure", ct);
            }

            var nonce = publicTestPart[0];
            var timeout = long.Parse(publicTestPart[1], CultureInfo.InvariantCulture);
            var timeOutDate = new DateTime(timeout);
            if (timeOutDate < DateTime.UtcNow) {
                return await RejectMultifactor(user, timer, "Timeout.", ct);
            }

            var message = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeout}:{dbUser.SecurityStamp}");
            var keyBytes = Convert.FromBase64String(configuration.TokenSigningSecret);

            using var hmac = new HMACSHA256(keyBytes);
            var expectedSignature = hmac.ComputeHash(message);

            var verify = Convert.FromBase64String(splitCode[1]);
            var arraysEqual = expectedSignature.ArraysAreEqual(verify);
            // Record before the cancellable padding wait so cancelling cannot skip the record.
            rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, arraysEqual);
            await timer.Wait(ct);

            return arraysEqual
                ? MultifactorResponse.Ok()
                : new MultifactorResponse(ResponseStatus.Unauthorized, "Validation failed");
        } catch (Exception ex) when (ex is not OperationCanceledException) {
            logger.LogMfaVerificationWarning(ex.Message, user.Id, ex);
            return await RejectMultifactor(user, timer, "Validation error", ct);
        }
#pragma warning restore CA1031 // Do not catch general exception types
    }

    private void Dispose(bool disposing) {
        if (!disposedValue) {
            if (disposing) {
                rng?.Dispose();
            }
            disposedValue = true;
        }
    }

    private static async Task<ApplicationUser?> ApplicationUserFindRecordByEmail(IIdentityContext ctx, string emailAddress, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(emailAddress);
        var normalizedName = emailAddress.Trim().ToUpperInvariant();
        return await ctx.UserFindRecordByEmail(normalizedName, ct);
    }

    private static async Task<ApplicationUser?> ApplicationUserById(IIdentityContext ctx, Guid userId, CancellationToken ct) {
        ArgumentOutOfRangeException.ThrowIfEqual(userId, Guid.Empty);
        return await ctx.UserFindRecord(userId, ct);
    }

    private static async Task<ApplicationUser?> ApplicationUserByName(IIdentityContext ctx, string? userName, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(userName);
        var normalizedName = userName.Trim().ToUpperInvariant();
        return await ctx.UserFindRecord(normalizedName, ct);
    }

    private static byte[] GenerateQrCode(string uri) {
        using QRCodeGenerator qrGenerator = new();
        var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);

        // PngByteQRCode produces a compressed PNG (~50 KB at 10 px/module) instead of
        // the ~4 MB uncompressed BMP that BitmapByteQRCode emits at the same scale.
        using PngByteQRCode qrCode = new(qrCodeData);
        return qrCode.GetGraphic(10);
    }

    private static string GenerateQrCodeUri(string username, string secret, string appName) {
        return $"otpauth://totp/{appName}:{username}?secret={secret}&issuer={appName}&digits=6";
    }

    /// <summary>
    /// Increments the failed access count for a user and locks account if threshold exceeded.
    /// </summary>
    /// <remarks>
    /// Runs with <see cref="CancellationToken.None"/> on purpose: a caller that cancels its request
    /// after a wrong password must not be able to skip the lockout counter. The work is one
    /// single-row read and update, so it is bounded.
    /// </remarks>
    /// <returns>
    /// The persistence status: <see cref="ResponseStatus.NotFound"/> when the user row is gone,
    /// <see cref="ResponseStatus.ServerError"/> when an exception was logged, otherwise the
    /// status of <see cref="N2.Core.Entity.IUnitOfWork.Complete(CancellationToken)"/>.
    /// </returns>
    private static async Task<ResponseStatus> IncrementAccessFailedCount(IIdentityContext ctx, ApplicationUser user, ILogger logger) {
#pragma warning disable CA1031 // Do not catch general exception types
        try {
            var dbUser = await ctx.User.FirstOrDefaultAsync(m => m.Id == user.Id, CancellationToken.None);
            if (dbUser == null) {
                return ResponseStatus.NotFound;
            }

            dbUser.AccessFailedCount++;

            // Lock account after 5 failed attempts (PCI-DSS allows up to 6)
            if (dbUser.AccessFailedCount >= 5) {
                dbUser.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15);
                dbUser.LockoutEnabled = true;

                logger.LogIncrementAccessFailedCount(dbUser.UserName ?? dbUser.Id.ToString(), dbUser.AccessFailedCount, dbUser.LockoutEnd);
            }

            var (status, _) = await ctx.Complete(CancellationToken.None);
            return status;
        } catch (Exception ex) when (ex is not OperationCanceledException) {
            logger.LogIncrementAccessFailedException(user.UserName ?? user.Id.ToString(), ex);
            return ResponseStatus.ServerError;
        }
#pragma warning restore CA1031 // Do not catch general exception types
    }

    /// <summary>
    /// Checks if a user account is currently locked out.
    /// </summary>
    private static bool IsLockedOut(ApplicationUser user) {
        if (!user.LockoutEnabled) {
            return false;
        }

        if (!user.LockoutEnd.HasValue) {
            return false;
        }

        return user.LockoutEnd.Value > DateTimeOffset.UtcNow;
    }

    private static DateTime TimeStepToTime(long timeStepMatched, int stepSize) {
        var window = timeStepMatched * (long)stepSize;
        var ticks = (window * TicksToSeconds) + UnicEpocTicks;
        return new DateTime(ticks);
    }

    private static (bool valid, string message) ValidateEmail(string email) {
        var valid = string.Empty;

        try {
            _ = new MailAddress(email);
        } catch (FormatException) {
            valid = "Invalid email format";
        } catch (ArgumentNullException) {
            valid = "Value is null or empty";
        } catch (ArgumentException e) {
            valid = e.Message;
        }

        return (valid.Length == 0, valid);
    }

    private static (bool success, string message) VerifyTwoFactorAuthentication(string code, string userTwoFactorSecret) {
        var otp = userTwoFactorSecret.TryConvertBase64String(out var data)
            ? new Totp(data)
            : new Totp(Base32Encoding.ToBytes(userTwoFactorSecret));

        var verified = otp.VerifyTotp(code, out var _, new VerificationWindow(1, 1));
        var remainingSeconds = otp.RemainingSeconds();
        if (verified) {
            return (true, $"{remainingSeconds} seconds remaining");
        }
        // Find problem
        var checkTime = otp.VerifyTotp(code, out var timeStepMatched, new VerificationWindow(100, 100));

        if (checkTime) {
            var time = TimeStepToTime(timeStepMatched, otp.Step);
            // still within bounds
            if (time < DateTime.UtcNow) {
                return (false, $"Otp code expired.");
            } else {
                return (false, $"Otp time skew error.");

            }
        } else {
            return (false, $"invalid OTP code.");
        }
    }

    private Task<IIdentityContext> CreateContext(CancellationToken ct) =>
        factory.Create(provider, connectionName, ct);

    /// <summary>
    /// Resets the failed access count for a user after successful authentication.
    /// </summary>
    /// <remarks>
    /// Runs with <see cref="CancellationToken.None"/> for the same reason as
    /// <see cref="IncrementAccessFailedCount"/>: the lockout counter is security state and its
    /// single-row update is bounded.
    /// </remarks>
    /// <returns>
    /// <see cref="ResponseStatus.NoContent"/> when there was nothing to reset,
    /// <see cref="ResponseStatus.NotFound"/> when the user row is gone,
    /// <see cref="ResponseStatus.ServerError"/> when an exception was logged, otherwise the
    /// status of <see cref="N2.Core.Entity.IUnitOfWork.Complete(CancellationToken)"/>.
    /// </returns>
    private async Task<ResponseStatus> ResetAccessFailedCount(IIdentityContext ctx, ApplicationUser user) {
        if (user.AccessFailedCount == 0) {
            return ResponseStatus.NoContent;
        }

#pragma warning disable CA1031 // Do not catch general exception types
        try {
            var dbUser = await ctx.User.FirstOrDefaultAsync(m => m.Id == user.Id, CancellationToken.None);
            if (dbUser == null) {
                return ResponseStatus.NotFound;
            }

            if (dbUser.AccessFailedCount == 0) {
                return ResponseStatus.NoContent;
            }

            logger.LogResetAccessFailedCount(dbUser.UserName ?? dbUser.Id.ToString(), dbUser.AccessFailedCount);

            dbUser.AccessFailedCount = 0;
            dbUser.LockoutEnd = null;

            var (status, _) = await ctx.Complete(CancellationToken.None);
            return status;
        } catch (Exception ex) when (ex is not OperationCanceledException) {
            logger.LogResetAccessCountFailure(user.UserName ?? user.Id.ToString(), ex);
            return ResponseStatus.ServerError;
        }
#pragma warning restore CA1031 // Do not catch general exception types
    }

    private async Task<(bool flowControl, ICommandResponse value, ApplicationUser? dbUser)> ValidateConfirmationToken(
        IIdentityContext ctx,
        Guid userId,
        string? userName,
        MultiFactorType multiFactorType,
        string? property,
        string confirmationToken,
        CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(confirmationToken);

        if (!allowedConfirmation.Contains(multiFactorType)) {
            return (flowControl: false, value: RequestResult.Unexpected($"Not supported here: {multiFactorType}"), null);
        }

        var dbUser = await ctx.UserFindRecord(userId, ct);
        if (dbUser == null) {
            return (flowControl: false, value: RequestResult.NotFound(), null);
        }
        if (multiFactorType == MultiFactorType.Email && (dbUser.UserName != userName || dbUser.Email != property)) {
            return (flowControl: false, value: RequestResult.NotFound(), null);
        }
        if (multiFactorType == MultiFactorType.Sms && (dbUser.UserName != userName || dbUser.PhoneNumber != property)) {
            return (flowControl: false, value: RequestResult.NotFound(), null);
        }

        var verified = await ValidateMultifactor(dbUser, confirmationToken, ct);
        if (verified == null) {
            return (flowControl: false, value: RequestResult.NotFound(), dbUser);
        }

        return (flowControl: verified.Status.IsSuccess(), value: verified, dbUser);
    }

    public async Task<ISecretOwner?> GetSecretOwner(Guid id, CancellationToken ct) {
        using var ctx = await CreateContext(ct);
        var dbUser = await ctx.UserFindRecord(id, ct);
        if (dbUser == null) {
            return null;
        }
        if (dbUser.SecretKeyMaterial == null || dbUser.SecretKeyMaterial.Length == 0) {
            logger.LogMfaSecretNotSet(dbUser.UserName ?? dbUser.Id.ToString());
            throw new InvalidOperationException("SecretKeyMaterial is not set for user. Provision key material before creating secrets.");
        }
        return new SecretOwner(dbUser.Id, OwnerTypeCode.User, dbUser.SecretKeyMaterial);
    }

    public Task<ISecretManager> GetSecretManager(CancellationToken ct) {
        return Task.FromResult<ISecretManager>(
            new N2SecretManager(factory, provider, connectionName, configuration, logger, changeLogWriter, callerContext));
    }
}

