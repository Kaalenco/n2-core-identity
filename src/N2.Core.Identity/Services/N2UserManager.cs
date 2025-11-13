using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Data;

using OtpNet;

using QRCoder;

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Mail;
using System.Security.Cryptography;

namespace N2.Core.Identity.Services;

public class N2UserManager : IUserManager<ApplicationUser> {
    public N2UserManager(
        IIdentityContextFactory identityContextFactory,
        IConfiguration configuration,
        IPasswordHasher<ApplicationUser> passwordHasher,
        string catalog,
        ILogger<N2UserManager> logger) {
        this.factory = identityContextFactory;
        this.catalog = catalog;
        this.logger = logger;
        this.passwordHasher = passwordHasher;

        var appConfigSection = configuration?.GetSection(AuthenticationConfig.SectionName);
        if (appConfigSection != null) {
            appConfigSection.Bind(this.configuration);
        }
    }

    public bool SupportsUserEmail { get; }
    public async Task<ICommandResponse> AddToRoleAsync(ApplicationUser user, string role, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleItem = await ctx.ApplicationRoleAsync(normalizedName, token);
        if (roleItem == null) {
            return new RequestResult(ResponseStatus.NotAcceptable, $"Role '{role}' does not exist");
        }
        var isAssigned = await ctx.IdentityUserRoleAsync(user.Id, roleItem.Id, token);
        if (isAssigned != null) {
            return RequestResult.Ok();
        }
        IdentityUserRole<Guid> userRole = new() {
            RoleId = roleItem.Id,
            UserId = user.Id
        };
        await ctx.AddIdentityUserRoleAsync(userRole, token);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<bool> CanSignInAsync([NotNull] ApplicationUser user, CancellationToken token) {
        var ctx = await InitializeContextAsync();
        return await ctx.CanSignInAsync(user.Id);
    }

    public async Task<ICommandResponse> ConfirmEmailAsync([NotNull] ApplicationUser user, string confirmationToken, CancellationToken token) {
        var ctx = await InitializeContextAsync();
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

        var ctx = await InitializeContextAsync();
        var dbUser = await ApplicationUserByNameAsync(user.UserName ?? string.Empty, token);
        if (dbUser != null) {
            return new RequestResult(406, "Already exists");
        }

        ArgumentException.ThrowIfNullOrEmpty(user.UserName);
        ArgumentException.ThrowIfNullOrEmpty(user.Email);

        user.NormalizedUserName = user.UserName.ToUpperInvariant();
        user.NormalizedEmail = user.Email.ToUpperInvariant();
        user.EmailConfirmed = false;
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(50));
        user.PasswordHash = passwordHasher.HashPassword(user, password);
        await ctx.AddApplicationUserAsync(user, token);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> CreateRoleAsync(string role, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(role);
        var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleItem = await ctx.ApplicationRoleAsync(normalizedName, token);
        if (roleItem != null) {
            return new RequestResult(406, "Already exists");
        }
        roleItem = new ApplicationRole {
            Name = role,
            NormalizedName = normalizedName
        };
        await ctx.AddApplicationRoleAsync(roleItem, token);

        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> DeleteAsync([NotNull] ApplicationUser user, CancellationToken token) {
        var ctx = await InitializeContextAsync();
        ctx.RemoveApplicationUser(user);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public void Dispose() {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByEmailAsync(string emailAddress, CancellationToken token) {
        var result = await ApplicationUserByEmailAsync(emailAddress, token);
        return new ApplicationUserResponse(result);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByIdAsync(Guid userId, CancellationToken token) {
        var user = await ApplicationUserByIdAsync(userId, token);
        return new ApplicationUserResponse(user);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByNameAsync(string? userName, CancellationToken token) {
        var user = await ApplicationUserByNameAsync(userName, token);
        return new ApplicationUserResponse(user);
    }

    public async Task<ICommandResponse<string>> GenerateConfirmationTokenAsync([NotNull] ApplicationUser user, CancellationToken token) {
        if (user.Id == Guid.Empty) {
            var dbUser = await ApplicationUserByNameAsync(user.UserName, token);
            if (dbUser == null) {
                throw new InvalidOperationException("Invalid user");
            }
        }

        var nonce = RandomNumberGenerator.GetItems("ABCDEFGHIJKLMNOP1234567890".AsSpan(), 30).ToString();
        var timeOut = DateTime.UtcNow.AddDays(5).Ticks;

        var secret = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}:{user.SecurityStamp}");
        var key = System.Text.Encoding.UTF8.GetBytes(user.MfaSecret ?? "");
        var crypted = HMACSHA256.HashData(key, secret);

        var data = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}");
        var result = string.Concat(Convert.ToBase64String(data), '.', Convert.ToBase64String(crypted));
        return StringResponse.Accept(result);
    }

    public async Task<IListResponse<string>> GetRolesAsync([NotNull] ApplicationUser user, CancellationToken token) {
        var ctx = await InitializeContextAsync();
        var roles = await ctx.UserRolesAsync(user.Id);
        ListResponse<string> response = new(roles);
        return response;
    }

    public async Task<ICommandResponse<Guid>> GetUserIdAsync(ApplicationUser user, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        var ctx = await InitializeContextAsync();
        var normalizedName = user.UserName ?? "".ToUpperInvariant();
        var userRecord = await ctx.ApplicationUser.FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedName, token);
        var result = userRecord?.Id ?? Guid.Empty;
        return GuidResponse.Accept(result);
    }

    public async Task<ICommandResponse> IsInRoleAsync(ApplicationUser user, string role, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleItem = await ctx.ApplicationRoleAsync(normalizedName, token);
        if (roleItem == null) {
            return new GuidResponse(Guid.Empty, (int)ResponseStatus.NotFound, $"Role not found: {role}");
        }
        var isAssigned = await ctx.IdentityUserRoleAsync(user.Id, roleItem.Id, token);
        if (isAssigned != null) {
            return new GuidResponse(roleItem.Id, (int)ResponseStatus.Success, role);
        } else {
            return new GuidResponse(roleItem.Id, (int)ResponseStatus.NotAccepted, role);
        }
    }

    public async Task<ICommandResponse> RemoveFromRoleAsync(ApplicationUser user, string role, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleItem = await ctx.ApplicationRoleAsync(normalizedName, token);
        if (roleItem == null) {
            return new RequestResult(406, $"Role '{role}' does not exist");
        }
        var isAssigned = await ctx.IdentityUserRoleAsync(user.Id, roleItem.Id, token);
        if (isAssigned == null) {
            return RequestResult.Ok();
        }
        ctx.RemoveApplicationUserRole(isAssigned);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> RemoveRoleAsync(string role, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleItem = await ctx.ApplicationRole.FirstOrDefaultAsync(r => r.NormalizedName == normalizedName, token);
        if (roleItem == null) {
            return RequestResult.NotFound();
        }
        ctx.RemoveApplicationRole(roleItem);
        (var code, var message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<bool> RoleExistsAsync(string role, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleId = await ctx.ApplicationRoleAsync(normalizedName, token);
        return roleId != null;
    }

    public async Task<ICommandResponse> SetEmailAsync([NotNull] ApplicationUser user, string email, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(email);
        (var emailValid, var message) = ValidateEmail(email);
        if (!emailValid) {
            return new RequestResult(406, message);
        }
        var dbUser = await ApplicationUserByNameAsync(user.UserName ?? string.Empty, token);
        if (dbUser != null && dbUser.Id != user.Id) {
            return new RequestResult(406, "Already occupied");
        }
        user.Email = email;
        user.NormalizedEmail = email.ToUpperInvariant();
        user.EmailConfirmed = false;
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));

        (var status, var commitMessage) = await SaveChangesAsync();
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

        var code = new byte[10];
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

        var ctx = await InitializeContextAsync();
        var dbUser = await ApplicationUserByNameAsync(user.UserName, token);
        if (dbUser is null) {
            return new MultifactorResponse(ResponseStatus.NotFound, $"Could not find user {user.UserName}");
        }
        dbUser.MfaSecret = rngCode;
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
        var dbUser = await ApplicationUserByNameAsync(userName, token);
        if (dbUser != null && dbUser.Id != user.Id) {
            return new RequestResult(406, "Already occupied");
        }
        user.UserName = userName;
        user.NormalizedUserName = userName.ToUpperInvariant();
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));

        (var status, var commitMessage) = await SaveChangesAsync();
        return status.IsSuccess()
            ? RequestResult.Ok()
            : new RequestResult(status, $"Username not set for {user.Id}, {commitMessage}");
    }

    public async Task<ICommandResponse> ValidateAsync(ApplicationUser user, string password, CancellationToken token) {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(password);
        var ctx = await InitializeContextAsync();
        var normalizedUserName = user.UserName?.ToUpperInvariant() ?? string.Empty;
        var appUser = await ctx.ApplicationUser
            .Where(m => m.NormalizedUserName == normalizedUserName &&
                (m.LockoutEnd == null || m.LockoutEnd < DateTime.UtcNow)
            ).FirstOrDefaultAsync(token);
        if (appUser == null) {
            return new RequestResult(ResponseStatus.NotAccepted, "Not accepted");
        }
        var verificationResult = passwordHasher.VerifyHashedPassword(
            appUser,
            appUser.PasswordHash ?? "",
            password
        );

        if (verificationResult == PasswordVerificationResult.Failed) {
            return new RequestResult(ResponseStatus.NotAccepted, "Not accepted");
        }

        // Optional: Rehash if using outdated format
        if (verificationResult == PasswordVerificationResult.SuccessRehashNeeded) {
            appUser.PasswordHash = passwordHasher.HashPassword(appUser, password);
            await ctx.Complete();
        }
        return new RequestResult(ResponseStatus.Success, user.UserName ?? string.Empty);
    }

    private const int TimeForAuthenticationMs = 50;

    public async Task<ICommandResponse> ValidateMultifactorAsync(ApplicationUser user, string multifactorCode, CancellationToken token) {

        var timer = new TimeoutTimer(TimeForAuthenticationMs);

        if (user == null || string.IsNullOrEmpty(user.UserName)) {
            await timer.Wait();
            return MultifactorResponse.Failed("User name is not valid.");
        }

        var dbUser = await ApplicationUserByNameAsync(user.UserName, token);
        if (dbUser is null) {
            await timer.Wait();
            return new MultifactorResponse(ResponseStatus.Unauthorized, $"Could not find user {user.UserName}");
        }
        if (dbUser.MfaType == MultiFactorType.None) {
            await timer.Wait();
            return new MultifactorResponse(ResponseStatus.Accepted, "No multifactor required.");
        }
        if (string.IsNullOrEmpty(multifactorCode)) {
            await timer.Wait();
            return new MultifactorResponse(ResponseStatus.Unauthorized, "No multifactor code provided.");
        }
        if (string.IsNullOrEmpty(user.MfaSecret)) {
            LogMfaSecretNotSet(logger, user.UserName, null);
            await timer.Wait();
            return new MultifactorResponse(ResponseStatus.Conflict, "Multifactor is not configured.");
        }
        if (user.MfaType == MultiFactorType.Totp) {
            var verified = VerifyTwoFactorAuthentication(multifactorCode, user.MfaSecret);
            await timer.Wait();

            return !verified
                ? new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid Totp code.")
                : MultifactorResponse.Ok();
        } else if (user.MfaType is MultiFactorType.Sms or MultiFactorType.Email) {

#pragma warning disable CA1031 // Do not catch general exception types
            try {
                var splitCode = multifactorCode.Split('.', StringSplitOptions.RemoveEmptyEntries);
                if (splitCode.Length != 2) {
                    await timer.Wait();
                    return new MultifactorResponse(ResponseStatus.Unauthorized, "Invalid Mfa code parts.");
                }
                var publicPart = Convert.FromBase64String(splitCode[0]);
                var publicTestPart = System.Text.Encoding.UTF8.GetString(publicPart);
                var nonce = publicTestPart.Split(':')[0];
                var timeout = long.Parse(publicTestPart.Split(':')[1], CultureInfo.InvariantCulture);
                var timeOutDate = new DateTime(timeout);
                if (timeOutDate < DateTime.UtcNow) {
                    await timer.Wait();
                    return new MultifactorResponse(ResponseStatus.Unauthorized, "Timeout.");
                }

                var secret = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeout}:{user.SecurityStamp}");
                var key = System.Text.Encoding.UTF8.GetBytes(user.MfaSecret);
                var crypted = HMACSHA256.HashData(key, secret);


                var verify = Convert.FromBase64String(splitCode[1]);
                var arraysEqual = await crypted.ArraysAreEqual(verify);
                await timer.Wait();

                return arraysEqual
                    ? MultifactorResponse.Ok()
                    : new MultifactorResponse(ResponseStatus.Unauthorized, "Validation failed");
            } catch (Exception ex) {
                logMfaVerificationWarning(logger, ex.Message, multifactorCode, user.UserName, ex);
                await timer.Wait();
                return new MultifactorResponse(ResponseStatus.Unauthorized, "Validation error");
            }
#pragma warning restore CA1031 // Do not catch general exception types

        } else {
            return new MultifactorResponse(
                ResponseStatus.NotImplemented,
                $"Mutifactor {user.MfaType} is not available for {user.UserName}");
        }
    }

    protected virtual void Dispose(bool disposing) {
        if (!disposedValue) {
            if (disposing) {
                context?.Dispose();
                lockObject?.Dispose();
                rng?.Dispose();
            }
            disposedValue = true;
        }
    }

    private static readonly MultiFactorType[] allowedConfirmation = [MultiFactorType.Email, MultiFactorType.Sms];
    private static readonly Action<ILogger, string, Exception?> LogMfaSecretNotSet =
        LoggerMessage.Define<string>(
            LogLevel.Critical,
            new EventId(1, nameof(LogMfaSecretNotSet)),
            "MfaSecret is not set for user {UserName}");

    // Add this field to the N2UserManager class (preferably near other LoggerMessage delegates)
    private static readonly Action<ILogger, string, string, string, Exception?> logMfaVerificationWarning =
        LoggerMessage.Define<string, string, string>(
            LogLevel.Warning,
            new EventId(2, nameof(logMfaVerificationWarning)),
            "Error {Message} while verifying MFA token [{MultifactorCode}] for user [{UserName}].");

    private readonly string catalog;
    private readonly AuthenticationConfig configuration = new();
    private readonly IIdentityContextFactory factory;
    private readonly Semaphore lockObject = new(1, 1);
    private readonly ILogger<N2UserManager> logger;
    private readonly IPasswordHasher<ApplicationUser> passwordHasher;
    private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
    private IIdentityContext? context;
    private bool disposedValue;


    private static byte[] GenerateQrCode(string uri) {
        using QRCodeGenerator qrGenerator = new();
        var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);

        using BitmapByteQRCode qrCode = new(qrCodeData);
        return qrCode.GetGraphic(20);
    }

    private static string GenerateQrCodeUri(string username, string secret, string appName) {
        return $"otpauth://totp/{appName}:{username}?secret={secret}&issuer={appName}&digits=6";
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

    private static bool VerifyTwoFactorAuthentication(string code, string userTwoFactorSecret) {
        Totp otp = new(Base32Encoding.ToBytes(userTwoFactorSecret));
        return otp.VerifyTotp(code, out var _, new VerificationWindow(1, 1));
    }

    private async Task<ApplicationUser?> ApplicationUserByEmailAsync(string emailAddress, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(emailAddress);
        using var ctx = await InitializeContextAsync();
        var normalizedName = emailAddress.ToUpperInvariant();
        return await ctx.ApplicationUserByEmailAsync(normalizedName, token);
    }

    private async Task<ApplicationUser?> ApplicationUserByIdAsync(Guid userId, CancellationToken token) {
        ArgumentOutOfRangeException.ThrowIfEqual(userId, Guid.Empty);
        var ctx = await InitializeContextAsync();
        return await ctx.ApplicationUserAsync(userId, token);
    }

    private async Task<ApplicationUser?> ApplicationUserByNameAsync(string? userName, CancellationToken token) {
        ArgumentException.ThrowIfNullOrEmpty(userName);
        var ctx = await InitializeContextAsync();
        var normalizedName = userName.ToUpperInvariant();
        return await ctx.ApplicationUserAsync(normalizedName, token);
    }

    private async Task<IIdentityContext> InitializeContextAsync() {
        if (context != null) {
            return context;
        }

        lockObject.WaitOne();
        try {
            context = await factory.CreateAsync(catalog);
        } finally {
            lockObject.Release();
        }
        return context;
    }
    private async Task<(ResponseStatus, string?)> SaveChangesAsync() {
        var ctx = await InitializeContextAsync();
        var result = await ctx.Complete();
        return result;
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

        var dbUser = await ctx.ApplicationUserAsync(userId, token);
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
}