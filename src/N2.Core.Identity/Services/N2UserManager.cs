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

public sealed class N2UserManager : IUserManager<ApplicationUser>, IHaveSecrets {

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
            new EventId(1001, nameof(RotateMfaSecretsAsync)),
            "RotateMfaSecretsAsync: could not decrypt MfaSecret for user {UserId} — skipping.");

    private static readonly Action<ILogger, int, Exception?> _logRotateMfaSecretRotated =
        LoggerMessage.Define<int>(
            LogLevel.Information,
            new EventId(1002, nameof(RotateMfaSecretsAsync)),
            "\"RotateMfaSecretsAsync: re-encrypted {Count} MfaSecret(s).\"");

    private static readonly MultiFactorType[] allowedConfirmation = [MultiFactorType.Email, MultiFactorType.Sms];
    private readonly AuthenticationConfig configuration;

    private readonly DatabaseProvider provider;

    /// <summary>
    /// Gets the name of the database connection used for establishing connections.
    /// </summary>
    private readonly string connectionName;
    private readonly IIdentityContextFactory factory;
    private readonly ILogger<N2UserManager> logger;

    // Intentionally not disposed: disposing a kernel-backed Semaphore while another thread
    // is blocked on WaitOne() causes an ObjectDisposedException. The OS reclaims the handle on exit.
#pragma warning disable CA2213
    private readonly Semaphore lockObject = new(1, 1);
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
        DatabaseProvider provider = DatabaseProvider.SqlServer) {
        this.factory = identityContextFactory;
        this.connectionName = connectionName;
        this.provider = provider;
        this.logger = logger;
        this.rateLimiter = rateLimiter;
        this.passwordHasher = passwordHasher;

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

    public async Task<ICommandResponse> AddToRoleAsync(ApplicationUser user, string role, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContextAsync();
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.RoleFindRecord(normalizedName, token);
        if (roleItem == null) {
            return new RequestResult(ResponseStatus.NotAcceptable, $"Role '{role}' does not exist");
        }
        var isAssigned = await ctx.UserRoleFindRecord(user.Id, roleItem.Id, token);
        if (isAssigned != null) {
            return RequestResult.Ok();
        }
        IdentityUserRole<Guid> userRole = new() {
            RoleId = roleItem.Id,
            UserId = user.Id
        };
        await ctx.UserRoleAdd(userRole, token);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<bool> ApplicationUserCanSignIn([NotNull] ApplicationUser user, CancellationToken token) {
        using var ctx = await CreateContextAsync();
        return await ctx.UserCanSignIn(user.Id, token);
    }

    Task<bool> IUserManager<ApplicationUser>.CanSignInAsync(ApplicationUser user, CancellationToken token)
        => ApplicationUserCanSignIn(user, token);

    public async Task<ICommandResponse> ConfirmEmailAsync([NotNull] ApplicationUser user, string confirmationToken, CancellationToken token) {
        using var ctx = await CreateContextAsync();
        var (flowControl, value, dbUser) = await ValidateConfirmationToken(ctx, user.Id, user.UserName, MultiFactorType.Email, user.Email, confirmationToken, token);
        if (!flowControl) {
            return value;
        }

        // dbUser should be set
        dbUser!.LockoutEnabled = true;
        dbUser!.EmailConfirmed = true;
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> CreateAsync([NotNull] ApplicationUser user, string password, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(password);

        using var ctx = await CreateContextAsync();
        var dbUser = await ApplicationUserByNameAsync(ctx, user.UserName ?? string.Empty, token);
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
        await ctx.UserAdd(user, token);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> CreateRoleAsync(string role, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContextAsync();
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.RoleFindRecord(normalizedName, token);
        if (roleItem != null) {
            return new RequestResult(406, "Already exists");
        }
        roleItem = new ApplicationRole {
            Name = role,
            NormalizedName = normalizedName
        };
        await ctx.RoleAdd(roleItem, token);

        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> DeleteAsync([NotNull] ApplicationUser user, CancellationToken token) {
        using var ctx = await CreateContextAsync();
        ctx.UserDelete(user);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public void Dispose() {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByEmailAsync(string emailAddress, CancellationToken token) {
        using var ctx = await CreateContextAsync();
        var result = await ApplicationUserFindRecordByEmail(ctx, emailAddress, token);
        return new ApplicationUserResponse(result);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByIdAsync(Guid userId, CancellationToken token) {
        using var ctx = await CreateContextAsync();
        var user = await ApplicationUserByIdAsync(ctx, userId, token);
        return new ApplicationUserResponse(user);
    }

    public async Task<ICommandResponse<ApplicationUser>> ApplicationUserFind(string? userName, CancellationToken token) {
        using var ctx = await CreateContextAsync();
        var user = await ApplicationUserByNameAsync(ctx, userName, token);
        return new ApplicationUserResponse(user);
    }

    Task<ICommandResponse<ApplicationUser>> IUserManager<ApplicationUser>.FindByNameAsync(string userName, CancellationToken token)
        => ApplicationUserFind(userName, token);

    public async Task<ICommandResponse<string>> GenerateConfirmationTokenAsync([NotNull] ApplicationUser user, CancellationToken token) {

        using var ctx = await CreateContextAsync();
        var mfaType = user.MfaType;
        ApplicationUser? dbUser;
        if (user.Id == Guid.Empty) {
            dbUser = await ApplicationUserByNameAsync(ctx, user.UserName, token);

        } else {
            dbUser = await ApplicationUserByIdAsync(ctx, user.Id, token);
        }
        if (dbUser == null) {
            throw new InvalidOperationException("Invalid user");
        }

        if (mfaType == MultiFactorType.None) {
            dbUser.MfaSecret = string.Empty;
            dbUser.MfaType = mfaType;
            await ctx.Complete();
            return StringResponse.Accept(string.Empty);
        }

        var randomBytes = RandomNumberGenerator.GetBytes(32);
        var secret = Convert.ToBase64String(randomBytes);

        dbUser.MfaSecret = MfaSecretEncryption.Encrypt(secret, configuration.MfaTokenSecret);
        dbUser.MfaType = mfaType;
        await ctx.Complete();

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

    public async Task<IListResponse<string>> GetRolesAsync([NotNull] ApplicationUser user, CancellationToken token) {
        using var ctx = await CreateContextAsync();
        var roles = await ctx.UserGetRoles(user.Id, token);
        ListResponse<string> response = new(roles);
        return response;
    }

    public async Task<ICommandResponse<Guid>> GetUserIdAsync(ApplicationUser user, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        using var ctx = await CreateContextAsync();
        var normalizedName = (user.UserName ?? "").Trim().ToUpperInvariant();
        var userRecord = await ctx.User.FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedName, token);
        var result = userRecord?.Id ?? Guid.Empty;
        return GuidResponse.Accept(result);
    }

    public async Task<ICommandResponse> IsInRoleAsync(ApplicationUser user, string role, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContextAsync();
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.RoleFindRecord(normalizedName, token);
        if (roleItem == null) {
            return new GuidResponse(Guid.Empty, (int)ResponseStatus.NotFound, $"Role not found: {role}");
        }
        var isAssigned = await ctx.UserRoleFindRecord(user.Id, roleItem.Id, token);
        if (isAssigned != null) {
            return new GuidResponse(roleItem.Id, (int)ResponseStatus.Success, role);
        } else {
            return new GuidResponse(roleItem.Id, (int)ResponseStatus.NotAccepted, role);
        }
    }

    public async Task<ICommandResponse> RemoveFromRoleAsync(ApplicationUser user, string role, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContextAsync();
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.RoleFindRecord(normalizedName, token);
        if (roleItem == null) {
            return new RequestResult(406, $"Role '{role}' does not exist");
        }
        var isAssigned = await ctx.UserRoleFindRecord(user.Id, roleItem.Id, token);
        if (isAssigned == null) {
            return RequestResult.Ok();
        }
        ctx.UserRoleDelete(isAssigned);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> RemoveRoleAsync(string role, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContextAsync();
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleItem = await ctx.Role.FirstOrDefaultAsync(r => r.NormalizedName == normalizedName, token);
        if (roleItem == null) {
            return RequestResult.NotFound();
        }
        ctx.RoleDelete(roleItem);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<bool> RoleExistsAsync(string role, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await CreateContextAsync();
        var normalizedName = role.Trim().ToUpperInvariant();
        var roleId = await ctx.RoleFindRecord(normalizedName, token);
        return roleId != null;
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
    public async Task<int> RotateMfaSecretsAsync(CancellationToken cancellationToken = default) {
        if (string.IsNullOrEmpty(configuration.MfaTokenSecret2)) {
            throw new InvalidOperationException(
                "MfaTokenSecret2 must contain the retiring key before rotation can proceed.");
        }

        using var ctx = await CreateContextAsync();
        var users = await ctx.User
            .Where(u => u.MfaSecret != null && u.MfaSecret != string.Empty)
            .ToListAsync(cancellationToken);

        var rotated = 0;

        foreach (var user in users) {
            var plaintext = MfaSecretEncryption.TryDecrypt(
                user.MfaSecret,
                configuration.MfaTokenSecret,
                configuration.MfaTokenSecret2);

            if (plaintext == null) {
                _logRotateMfaSecretDecryptionFailed(logger, user.Id, null);
                continue;
            }

            // Already encrypted with the primary key — check by re-encrypting only if plaintext
            // was decrypted via the secondary key (i.e. the stored value used the old key).
            var reEncrypted = MfaSecretEncryption.Encrypt(plaintext, configuration.MfaTokenSecret);
            if (reEncrypted == user.MfaSecret) {
                // Already encrypted with primary key — no change needed
                continue;
            }

            user.MfaSecret = reEncrypted;
            rotated++;
        }

        if (rotated > 0) {
            await ctx.Complete();
            _logRotateMfaSecretRotated(logger, rotated, null);
        }

        return rotated;
    }

    public async Task<ICommandResponse> SetEmailAsync([NotNull] ApplicationUser user, string email, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(email);
        (var emailValid, var message) = ValidateEmail(email);
        if (!emailValid) {
            return new RequestResult(406, message);
        }
        using var ctx = await CreateContextAsync();
        var dbUser = await ApplicationUserByNameAsync(ctx, user.UserName ?? string.Empty, token);
        if (dbUser != null && dbUser.Id != user.Id) {
            return new RequestResult(406, "Already occupied");
        }
        user.Email = email.Trim();
        user.NormalizedEmail = email.Trim().ToUpperInvariant();
        user.EmailConfirmed = false;
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        (var status, var commitMessage) = await ctx.Complete();
        return status.IsSuccess()
            ? RequestResult.Ok()
            : new RequestResult(status, $"Email not set for {user.Id}, {commitMessage}");
    }

    public async Task<ICommandResponse<MultiFactorProperties>> SetMultifactorAsync(
        ApplicationUser user,
        MultiFactorType mfaType,
        string mfaToken,
        CancellationToken token) {
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

                userUri = GenerateQrCodeUri(user.UserName, rngCode, configuration.TwoFactorTotpName);
                qrCode = GenerateQrCode(userUri);
                break;

            default:
                return MultifactorResponse.Failed($"Not supported : {mfaType}.");
        }

        using var ctx = await CreateContextAsync();
        var dbUser = await ApplicationUserByNameAsync(ctx, user.UserName, token);
        if (dbUser is null) {
            return new MultifactorResponse(ResponseStatus.NotFound, $"Could not find user {user.UserName}");
        }
        dbUser.MfaSecret = MfaSecretEncryption.Encrypt(rngCode, configuration.MfaTokenSecret);
        dbUser.MfaType = mfaType;
        (var responseCode, var message) = await ctx.Complete();

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

    public async Task<ICommandResponse> SetUserNameAsync([NotNull] ApplicationUser user, string userName, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(userName);
        using var ctx = await CreateContextAsync();
        var dbUser = await ApplicationUserByNameAsync(ctx, userName, token);
        if (dbUser != null && dbUser.Id != user.Id) {
            return new RequestResult(406, "Already occupied");
        }
        user.UserName = userName.Trim();
        user.NormalizedUserName = userName.Trim().ToUpperInvariant();
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        (var status, var commitMessage) = await ctx.Complete();
        return status.IsSuccess()
            ? RequestResult.Ok()
            : new RequestResult(status, $"Username not set for {user.Id}, {commitMessage}");
    }

    public void UpdateRateLimiter(Guid userId, string? userName, DateTime newEndDate) {
        rateLimiter.UpdateRateLimit(userId, userName, newEndDate);
    }

    public async Task<ICommandResponse> ValidateAsync(ApplicationUser user, string password, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(password);
        var timer = new TimeoutTimer(TimeForAuthenticationMs);

        // Check lockout status FIRST
        if (IsLockedOut(user)) {
            var lockoutEnd = user.LockoutEnd!.Value;
            var remainingTime = lockoutEnd - DateTimeOffset.UtcNow;

            logger.LogUserLockedOut(user.UserName ?? user.Id.ToString(), lockoutEnd, Math.Ceiling(remainingTime.TotalMinutes));

            await timer.Wait();
            return new RequestResult(423, $"Account is locked. Try again after {lockoutEnd:u}");
        }

        using var ctx = await CreateContextAsync();
        var normalizedUserName = user.UserName?.ToUpperInvariant() ?? string.Empty;
        var appUser = await ctx.User
            .Where(m => m.NormalizedUserName == normalizedUserName &&
                (m.LockoutEnd == null || m.LockoutEnd < DateTime.UtcNow)
            ).FirstOrDefaultAsync(token);
        if (appUser == null) {
            await timer.Wait();
            return new RequestResult(ResponseStatus.NotAccepted, "Not accepted");
        }

        var verificationResult = passwordHasher.VerifyHashedPassword(
            appUser,
            appUser.PasswordHash ?? "",
            password
        );

        if (verificationResult == PasswordVerificationResult.Failed) {
            await IncrementAccessFailedCountAsync(ctx, appUser, logger, token);
            return new RequestResult(ResponseStatus.NotAccepted, "Not accepted");
        }

        // Password verified successfully - reset failed count
        await ResetAccessFailedCountAsync(ctx, appUser, token);

        // Optional: Rehash if using outdated format
        if (verificationResult == PasswordVerificationResult.SuccessRehashNeeded) {
            appUser.PasswordHash = passwordHasher.HashPassword(appUser, password);
            await ctx.Complete();
        }
        return new RequestResult(ResponseStatus.Success, user.UserName ?? string.Empty);
    }
    public async Task<ICommandResponse> ValidateMultifactorAsync(ApplicationUser user, string multifactorCode, CancellationToken token) {

        ArgumentNullException.ThrowIfNull(user);
        var timer = new TimeoutTimer(TimeForAuthenticationMs);
        lockObject.WaitOne();
        try {
            // Check rate limiting FIRST (before any validation)
            var (rateLimitCheck, remainingTime) = rateLimiter.CheckRateLimit(user.Id, user.NormalizedUserName);
            if (!rateLimitCheck) {
                await timer.Wait();
                return new MultifactorResponse(
                    ResponseStatus.Unauthorized,
                    $"Too many failed MFA attempts. Account locked for {remainingTime} more minutes."
                );
            }

            using var ctx = await CreateContextAsync();

            if (user == null || string.IsNullOrEmpty(user.UserName)) {
                await timer.Wait();
                return MultifactorResponse.Failed("User name is not valid.");
            }

            var dbUser = await ApplicationUserByNameAsync(ctx, user.UserName, token);
            if (dbUser is null) {
                await timer.Wait();
                rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
                return new MultifactorResponse(ResponseStatus.Unauthorized, $"Could not find user {user.UserName}");
            }
            if (dbUser.MfaType == MultiFactorType.None) {
                await timer.Wait();
                return new MultifactorResponse(ResponseStatus.Accepted, "No multifactor required.");
            }

            string[] splitCode = [];
            if (dbUser.MfaType == MultiFactorType.Email) {
                if (string.IsNullOrEmpty(multifactorCode) || !multifactorCode.Contains('.', StringComparison.Ordinal)) {
                    await timer.Wait();
                    rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
                    return new MultifactorResponse(ResponseStatus.Unauthorized, "No multifactor code provided.");
                }

                splitCode = multifactorCode.Split('.');
                if (splitCode.Length != 2) {
                    await timer.Wait();
                    rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
                    return new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid token format");
                }
            }

            if (string.IsNullOrEmpty(user.MfaSecret)) {
                logger.LogMfaSecretNotSet(user.UserName);
                await timer.Wait();
                return new MultifactorResponse(ResponseStatus.Conflict, "Multifactor is not configured.");
            }

            if (dbUser.MfaType == MultiFactorType.Totp) {
                var decryptedSecret = MfaSecretEncryption.TryDecrypt(dbUser.MfaSecret, configuration.MfaTokenSecret, configuration.MfaTokenSecret2);
                var (verified, message) = VerifyTwoFactorAuthentication(multifactorCode, decryptedSecret ?? "");
                await timer.Wait();

                if (verified) {
                    rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, true);
                    return MultifactorResponse.Ok();
                } else {
                    rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
                    return new MultifactorResponse(ResponseStatus.Unauthorized, message);
                }
            } else if (dbUser.MfaType is MultiFactorType.Sms or MultiFactorType.Email) {

#pragma warning disable CA1031 // Do not catch general exception types
                try {
                    var publicPart = Convert.FromBase64String(splitCode[0]);
                    var publicTestPart = System.Text.Encoding.UTF8.GetString(publicPart).Split(':', StringSplitOptions.RemoveEmptyEntries);

                    if (publicTestPart.Length != 2) {
                        await timer.Wait();
                        rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
                        return new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid token structure");
                    }

                    var nonce = publicTestPart[0];
                    var timeout = long.Parse(publicTestPart[1], CultureInfo.InvariantCulture);
                    var timeOutDate = new DateTime(timeout);
                    if (timeOutDate < DateTime.UtcNow) {
                        await timer.Wait();
                        rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
                        return new MultifactorResponse(ResponseStatus.Unauthorized, "Timeout.");
                    }

                    var message = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeout}:{dbUser.SecurityStamp}");
                    var keyBytes = Convert.FromBase64String(configuration.TokenSigningSecret);

                    using var hmac = new HMACSHA256(keyBytes);
                    var expectedSignature = hmac.ComputeHash(message);

                    var verify = Convert.FromBase64String(splitCode[1]);
                    var arraysEqual = await expectedSignature.ArraysAreEqual(verify);
                    await timer.Wait();

                    rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, arraysEqual);

                    return arraysEqual
                        ? MultifactorResponse.Ok()
                        : new MultifactorResponse(ResponseStatus.Unauthorized, "Validation failed");
                } catch (Exception ex) {
                    logger.LogMfaVerificationWarning(ex.Message, multifactorCode, user.UserName, ex);
                    await timer.Wait();
                    rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
                    return new MultifactorResponse(ResponseStatus.Unauthorized, "Validation error");
                }
#pragma warning restore CA1031 // Do not catch general exception types

            } else {
                rateLimiter.RecordAttempt(user.Id, user.NormalizedUserName, false);
                return new MultifactorResponse(
                    ResponseStatus.NotImplemented,
                    $"Multifactor {user.MfaType} is not available for {user.UserName}");
            }
        } finally {
            lockObject.Release();
        }
    }

    private void Dispose(bool disposing) {
        if (!disposedValue) {
            if (disposing) {
                rng?.Dispose();
            }
            disposedValue = true;
        }
    }

    private static async Task<ApplicationUser?> ApplicationUserFindRecordByEmail(IIdentityContext ctx, string emailAddress, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(emailAddress);
        var normalizedName = emailAddress.Trim().ToUpperInvariant();
        return await ctx.UserFindRecordByEmail(normalizedName, token);
    }

    private static async Task<ApplicationUser?> ApplicationUserByIdAsync(IIdentityContext ctx, Guid userId, CancellationToken token) {
        ArgumentOutOfRangeException.ThrowIfEqual(userId, Guid.Empty);
        return await ctx.UserFindRecord(userId, token);
    }

    private static async Task<ApplicationUser?> ApplicationUserByNameAsync(IIdentityContext ctx, string? userName, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(userName);
        var normalizedName = userName.Trim().ToUpperInvariant();
        return await ctx.UserFindRecord(normalizedName, token);
    }

    private static long CalculateTimeStepFromTimestamp(DateTime timestamp, long stepSize) {
        var unixTimestamp = (timestamp.Ticks - UnicEpocTicks) / TicksToSeconds;
        var window = unixTimestamp / stepSize;
        return window;
    }

    private static byte[] GenerateQrCode(string uri) {
        using QRCodeGenerator qrGenerator = new();
        var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);

        using BitmapByteQRCode qrCode = new(qrCodeData);
        return qrCode.GetGraphic(20);
    }

    private static string GenerateQrCodeUri(string username, string secret, string appName) {
        return $"otpauth://totp/{appName}:{username}?secret={secret}&issuer={appName}&digits=6";
    }

    /// <summary>
    /// Increments the failed access count for a user and locks account if threshold exceeded.
    /// </summary>
    private static async Task IncrementAccessFailedCountAsync(IIdentityContext ctx, ApplicationUser user, ILogger logger, CancellationToken token = default) {
#pragma warning disable CA1031 // Do not catch general exception types
        try {
            var dbUser = await ctx.User.FirstOrDefaultAsync(m => m.Id == user.Id, token);
            if (dbUser == null) {
                return;
            }

            dbUser.AccessFailedCount++;

            // Lock account after 5 failed attempts (PCI-DSS allows up to 6)
            if (dbUser.AccessFailedCount >= 5) {
                dbUser.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15);
                dbUser.LockoutEnabled = true;

                logger.LogIncrementAccessFailedCount(dbUser.UserName ?? dbUser.Id.ToString(), dbUser.AccessFailedCount, dbUser.LockoutEnd);
            }

            await ctx.Complete();
        } catch (Exception ex) {
            logger.LogIncrementAccessFailedException(user.UserName ?? user.Id.ToString(), ex);
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

    private Task<IIdentityContext> CreateContextAsync() =>
        factory.CreateAsync(provider, connectionName);

    /// <summary>
    /// Resets the failed access count for a user after successful authentication.
    /// </summary>
    private async Task ResetAccessFailedCountAsync(IIdentityContext ctx, ApplicationUser user, CancellationToken token = default) {
        if (user.AccessFailedCount == 0) {
            return;
        }

#pragma warning disable CA1031 // Do not catch general exception types
        try {
            var dbUser = await ctx.User.FirstOrDefaultAsync(m => m.Id == user.Id, token);
            if (dbUser == null) {
                return;
            }

            if (dbUser.AccessFailedCount > 0) {
                logger.LogResetAccessFailedCount(dbUser.UserName ?? dbUser.Id.ToString(), dbUser.AccessFailedCount);

                dbUser.AccessFailedCount = 0;
                dbUser.LockoutEnd = null;

                await ctx.Complete();
            }
        } catch (Exception ex) {
            logger.LogResetAccessCountFailure(user.UserName ?? user.Id.ToString(), ex);
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
        CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(confirmationToken);

        if (!allowedConfirmation.Contains(multiFactorType)) {
            return (flowControl: false, value: RequestResult.Unexpected($"Not supported here: {multiFactorType}"), null);
        }

        var dbUser = await ctx.UserFindRecord(userId, token);
        if (dbUser == null) {
            return (flowControl: false, value: RequestResult.NotFound(), null);
        }
        if (multiFactorType == MultiFactorType.Email && (dbUser.UserName != userName || dbUser.Email != property)) {
            return (flowControl: false, value: RequestResult.NotFound(), null);
        }
        if (multiFactorType == MultiFactorType.Sms && (dbUser.UserName != userName || dbUser.PhoneNumber != property)) {
            return (flowControl: false, value: RequestResult.NotFound(), null);
        }

        var verified = await ValidateMultifactorAsync(dbUser, confirmationToken, token);
        if (verified == null) {
            return (flowControl: false, value: RequestResult.NotFound(), dbUser);
        }

        return (flowControl: verified.Status.IsSuccess(), value: verified, dbUser);
    }

    public async Task<ISecretOwner?> GetSecretOwner(Guid id, CancellationToken token) {
        using var ctx = await CreateContextAsync();
        var dbUser = await ctx.UserFindRecord(id, token);
        if (dbUser == null) {
            return null;
        }
        if (dbUser.SecretKeyMaterial == null || dbUser.SecretKeyMaterial.Length == 0) {
            logger.LogMfaSecretNotSet(dbUser.UserName ?? dbUser.Id.ToString());
            throw new InvalidOperationException("SecretKeyMaterial is not set for user. Provision key material before creating secrets.");
        }
        return new SecretOwner(dbUser.Id, OwnerTypeCode.User, dbUser.SecretKeyMaterial);
    }

    public Task<ISecretManager> GetSecretManager(CancellationToken token) {
        throw new NotSupportedException(
            "ISecretManager is not directly constructable from N2UserManager. " +
            "Register an ISecretManager implementation in the DI container and inject it where needed.");
    }
}

