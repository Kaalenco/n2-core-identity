using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Models;

namespace N2.Core.Identity.Services;

#pragma warning disable CA1725
// Using ct and not token for CancellationToken parameter names in async methods
// is a common convention in .NET, and it is more concise. The CA1725 warning is not relevant in this context.

public sealed class N2TokenService : IN2TokenService {
    private static readonly TimeSpan GracePeriod = TimeSpan.FromSeconds(2);
    private const string GraceCacheKeyPrefix = "rt_refresh:";

    private readonly IWebTokenGenerator tokenGenerator;
    private readonly IUserManager<ApplicationUser> userManager;
    private readonly IIdentityContextFactory contextFactory;
    private readonly IMemoryCache cache;
    private readonly JwtSettings jwtSettings;
    private readonly ILogger<N2TokenService> logger;

    public N2TokenService(
        IWebTokenGenerator tokenGenerator,
        IUserManager<ApplicationUser> userManager,
        IIdentityContextFactory contextFactory,
        IMemoryCache cache,
        AuthenticationConfig config,
        ILogger<N2TokenService> logger) {
        this.tokenGenerator = tokenGenerator;
        this.userManager = userManager;
        this.contextFactory = contextFactory;
        this.cache = cache;
        this.jwtSettings = config?.JwtSettings ?? new JwtSettings();
        this.logger = logger;
    }

    public async Task<TokenPairResult> IssueTokenPair(IUserContext userContext, int timeoutInMinutes, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(userContext);

        var accessToken = tokenGenerator.GenerateWebToken(userContext, timeoutInMinutes);
        var refreshTokenValue = tokenGenerator.GenerateRefreshToken();
        var expiresAt = tokenGenerator.RefreshTokenExpiry();
        var stamp = (userContext as AspNetUserContext)?.SecurityStamp;

        using var db = await contextFactory.CreateAsync();
        db.RefreshTokenAdd(new ApplicationRefreshToken {
            ApplicationUserId = userContext.PublicId,
            Token = refreshTokenValue,
            ExpiresAt = expiresAt,
            SecurityStamp = stamp
        });

        var (code, message) = await db.Complete();
        if (!code.IsSuccess()) {
            TokenIssueFailed(logger, message ?? "unknown error", null);
            throw new InvalidOperationException($"Failed to persist refresh token: {message}");
        }

        return new TokenPairResult {
            AccessToken = accessToken,
            RefreshToken = refreshTokenValue,
            RefreshTokenExpiresAt = expiresAt
        };
    }

    public async Task<TokenPairResult?> Refresh(string refreshToken, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(refreshToken);

        var cacheKey = $"{GraceCacheKeyPrefix}{refreshToken}";
        if (cache.TryGetValue(cacheKey, out TokenPairResult? cached)) {
            return cached;
        }

        using var db = await contextFactory.CreateAsync();
        var storedToken = await db.RefreshTokenFind(refreshToken, ct);

        if (storedToken == null || !storedToken.IsValid) {
            TokenRefreshFailed(logger, "token not found or invalid", null);
            return null;
        }

        var user = await db.UserFindRecord(storedToken.ApplicationUserId, ct);
        if (user == null) {
            TokenRefreshFailed(logger, "user not found", null);
            return null;
        }

        if (storedToken.SecurityStamp != null && storedToken.SecurityStamp != user.SecurityStamp) {
            TokenRefreshFailed(logger, "security stamp mismatch — revoking all tokens for user", null);
            await db.RefreshTokenRevokeAll(storedToken.ApplicationUserId, ct);
            await db.Complete();
            return null;
        }

        var newRefreshValue = tokenGenerator.GenerateRefreshToken();
        var expiresAt = tokenGenerator.RefreshTokenExpiry();

        db.RefreshTokenRevoke(storedToken);
        db.RefreshTokenAdd(new ApplicationRefreshToken {
            ApplicationUserId = user.Id,
            Token = newRefreshValue,
            ExpiresAt = expiresAt,
            SecurityStamp = user.SecurityStamp
        });

        var (code, message) = await db.Complete();
        if (!code.IsSuccess()) {
            TokenRefreshFailed(logger, message ?? "failed to persist rotated token", null);
            return null;
        }

        IList<(Guid TenantId, string TenantName, IReadOnlyList<string> Roles)> memberships = [];
        if (userManager is N2UserManager nm) {
            memberships = await nm.GetTenantMembershipsAsync(user, ct);
        }

        var userContext = new AspNetUserContext(user, memberships, [], null);
        var accessToken = tokenGenerator.GenerateWebToken(userContext, jwtSettings.TokenExpirationInMinutes);

        var result = new TokenPairResult {
            AccessToken = accessToken,
            RefreshToken = newRefreshValue,
            RefreshTokenExpiresAt = expiresAt
        };

        cache.Set(cacheKey, result, GracePeriod);
        return result;
    }

    public async Task<bool> RevokeRefreshToken(string refreshToken, CancellationToken ct) {
        ArgumentException.ThrowIfNullOrEmpty(refreshToken);

        using var db = await contextFactory.CreateAsync();
        var storedToken = await db.RefreshTokenFind(refreshToken, ct);

        if (storedToken == null || storedToken.IsRevoked) {
            return false;
        }

        db.RefreshTokenRevoke(storedToken);
        await db.Complete();
        return true;
    }

    public Guid? ReadUserIdFromExpiredToken(string token) {
        if (string.IsNullOrEmpty(token)) {
            return null;
        }
#pragma warning disable CA1031
        try {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var claim = jwt.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            return claim?.Value is not null && Guid.TryParse(claim.Value, out var id) ? id : null;
        } catch {
            return null;
        }
#pragma warning restore CA1031
    }

    public Task<string> IssuePreAuthToken(IUserContext userContext, CancellationToken ct) {
        ArgumentNullException.ThrowIfNull(userContext);

        var key = Convert.FromBase64String(jwtSettings.Secret);
        key.ValidateKeySecurity();

        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256);

        List<Claim> claims = [new(ClaimTypes.NameIdentifier, userContext.PublicId.ToString())];
        if (!string.IsNullOrEmpty(userContext.Name)) {
            claims.Add(new(ClaimTypes.GivenName, userContext.Name));
        }
        if (!string.IsNullOrEmpty(userContext.Email)) {
            claims.Add(new(ClaimTypes.Email, userContext.Email));
        }
        if (!string.IsNullOrEmpty(userContext.PhoneNumber)) {
            claims.Add(new(ClaimTypes.MobilePhone, userContext.PhoneNumber));
        }

        var token = new JwtSecurityToken(
            jwtSettings.Issuer,
            jwtSettings.Audience,
            claims,
            expires: DateTime.UtcNow.AddMinutes(jwtSettings.PreAuthTokenExpirationInMinutes),
            signingCredentials: credentials);

        return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(token));
    }

    public async Task<bool> Logoff(Guid userId, CancellationToken ct) {
        using var db = await contextFactory.CreateAsync();
        await db.RefreshTokenRevokeAll(userId, ct);
        var (code, _) = await db.Complete();
        return code.IsSuccess();
    }

    private static readonly Action<ILogger, string, Exception?> TokenIssueFailed =
        LoggerMessage.Define<string>(
            LogLevel.Error,
            new EventId(21, nameof(TokenIssueFailed)),
            "Token issuance failed: {Reason}");

    private static readonly Action<ILogger, string, Exception?> TokenRefreshFailed =
        LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(22, nameof(TokenRefreshFailed)),
            "Token refresh failed: {Reason}");
}
