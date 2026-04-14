using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

using Moq;

using N2.Core.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Models;
using N2.Core.Identity.Services;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public sealed class UsingN2TokenService {
    private readonly Mock<IWebTokenGenerator> tokenGenerator = new();
    private readonly Mock<IUserManager<ApplicationUser>> userManager = new();
    private readonly Mock<IIdentityContextFactory> contextFactory = new();
    private readonly Mock<IIdentityContext> context = new();
    private readonly Mock<ILogger<N2TokenService>> logger = new();
    private readonly IMemoryCache cache;
    private readonly AuthenticationConfig config;

    private const string FakeAccessToken = "header.payload.signature";
    private const string TestStamp = "test-security-stamp";

    public UsingN2TokenService() {
        var services = new ServiceCollection();
        services.AddMemoryCache();
        cache = services.BuildServiceProvider().GetRequiredService<IMemoryCache>();

        config = new AuthenticationConfig {
            JwtSettings = new JwtSettings {
                Secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                Issuer = "test-issuer",
                Audience = "test-audience",
                TokenExpirationInMinutes = 5,
                PreAuthTokenExpirationInMinutes = 60,
                RefreshTokenExpirationInMinutes = 1440
            }
        };

        contextFactory.Setup(f => f.CreateAsync()).ReturnsAsync(context.Object);
        context.Setup(c => c.Complete()).ReturnsAsync((ResponseStatus.Success, (string?)null));
        context.Setup(c => c.RefreshTokenRevokeAll(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        tokenGenerator.Setup(g => g.GenerateWebToken(It.IsAny<IUserContext>(), It.IsAny<int>()))
            .Returns(FakeAccessToken);
        tokenGenerator.Setup(g => g.GenerateRefreshToken())
            .Returns(() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)));
        tokenGenerator.Setup(g => g.RefreshTokenExpiry())
            .Returns(DateTime.UtcNow.AddMinutes(1440));
    }

    private N2TokenService CreateService() =>
        new(tokenGenerator.Object, userManager.Object, contextFactory.Object, cache, config, logger.Object);

    private static ApplicationUser MakeUser(string stamp = TestStamp) => new() {
        Id = Guid.NewGuid(),
        UserName = "alice",
        Email = "alice@example.com",
        NormalizedUserName = "ALICE",
        SecurityStamp = stamp
    };

    private static AspNetUserContext MakeUserContext(ApplicationUser user) =>
        new(user, [], [], null);

    private static ApplicationRefreshToken MakeRefreshToken(
        ApplicationUser user,
        bool revoked = false,
        bool expired = false,
        string? stamp = TestStamp) =>
        new() {
            Id = Guid.NewGuid(),
            ApplicationUserId = user.Id,
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            IssuedAt = DateTime.UtcNow.AddHours(-1),
            ExpiresAt = expired ? DateTime.UtcNow.AddHours(-1) : DateTime.UtcNow.AddHours(23),
            RevokedAt = revoked ? DateTime.UtcNow.AddMinutes(-5) : null,
            SecurityStamp = stamp
        };

    private string GenerateRealJwt(Guid userId, int expiryMinutes = 5) {
        var key = Convert.FromBase64String(config.JwtSettings.Secret);
        var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            config.JwtSettings.Issuer,
            config.JwtSettings.Audience,
            [new Claim(ClaimTypes.NameIdentifier, userId.ToString())],
            expires: DateTime.UtcNow.AddMinutes(expiryMinutes),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    [TestMethod]
    public void N2TokenServiceCanInitialize() {
        var service = CreateService();
        Assert.IsNotNull(service);
    }

    // -------------------------------------------------------------------------
    // IssueTokenPair — guard clauses
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task IssueTokenPair_NullContext_ShouldThrow() {
        var service = CreateService();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => service.IssueTokenPair(null!, 5, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // IssueTokenPair — happy path
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task IssueTokenPair_ValidContext_ShouldReturnAccessToken() {
        var service = CreateService();
        var ctx = MakeUserContext(MakeUser());

        var result = await service.IssueTokenPair(ctx, 5, CancellationToken.None);

        Assert.AreEqual(FakeAccessToken, result.AccessToken);
    }

    [TestMethod]
    public async Task IssueTokenPair_ValidContext_ShouldReturnNonEmptyRefreshToken() {
        var service = CreateService();
        var ctx = MakeUserContext(MakeUser());

        var result = await service.IssueTokenPair(ctx, 5, CancellationToken.None);

        Assert.IsFalse(string.IsNullOrEmpty(result.RefreshToken));
    }

    [TestMethod]
    public async Task IssueTokenPair_ValidContext_ShouldPersistRefreshToken() {
        var service = CreateService();
        var ctx = MakeUserContext(MakeUser());

        await service.IssueTokenPair(ctx, 5, CancellationToken.None);

        context.Verify(c => c.RefreshTokenAdd(It.IsAny<ApplicationRefreshToken>()), Times.Once);
        context.Verify(c => c.Complete(), Times.Once);
    }

    [TestMethod]
    public async Task IssueTokenPair_WithSecurityStamp_ShouldStoreStampOnRefreshToken() {
        var service = CreateService();
        var user = MakeUser(stamp: "my-stamp");
        var ctx = MakeUserContext(user);

        ApplicationRefreshToken? captured = null;
        context.Setup(c => c.RefreshTokenAdd(It.IsAny<ApplicationRefreshToken>()))
            .Callback<ApplicationRefreshToken>(t => captured = t);

        await service.IssueTokenPair(ctx, 5, CancellationToken.None);

        Assert.IsNotNull(captured);
        Assert.AreEqual("my-stamp", captured!.SecurityStamp);
    }

    [TestMethod]
    public async Task IssueTokenPair_WithoutSecurityStamp_ShouldStoreNullStamp() {
        var service = CreateService();
        // IUserContext mock — no SecurityStamp (not an AspNetUserContext)
        var ctxMock = new Mock<IUserContext>();
        ctxMock.SetupGet(c => c.PublicId).Returns(Guid.NewGuid());

        ApplicationRefreshToken? captured = null;
        context.Setup(c => c.RefreshTokenAdd(It.IsAny<ApplicationRefreshToken>()))
            .Callback<ApplicationRefreshToken>(t => captured = t);

        await service.IssueTokenPair(ctxMock.Object, 5, CancellationToken.None);

        Assert.IsNull(captured?.SecurityStamp);
    }

    // -------------------------------------------------------------------------
    // Refresh — guard clauses
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task Refresh_EmptyToken_ShouldThrow() {
        var service = CreateService();

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.Refresh(string.Empty, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // Refresh — invalid token paths
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task Refresh_TokenNotFound_ShouldReturnNull() {
        context.Setup(c => c.RefreshTokenFind(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((ApplicationRefreshToken?)null);
        var service = CreateService();

        var result = await service.Refresh("unknown-token", CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task Refresh_ExpiredToken_ShouldReturnNull() {
        var user = MakeUser();
        var token = MakeRefreshToken(user, expired: true);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        var service = CreateService();

        var result = await service.Refresh(token.Token, CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task Refresh_RevokedToken_ShouldReturnNull() {
        var user = MakeUser();
        var token = MakeRefreshToken(user, revoked: true);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        var service = CreateService();

        var result = await service.Refresh(token.Token, CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task Refresh_UserNotFound_ShouldReturnNull() {
        var user = MakeUser();
        var token = MakeRefreshToken(user);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync((ApplicationUser?)null);
        var service = CreateService();

        var result = await service.Refresh(token.Token, CancellationToken.None);

        Assert.IsNull(result);
    }

    // -------------------------------------------------------------------------
    // Refresh — security stamp mismatch
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task Refresh_SecurityStampMismatch_ShouldReturnNull() {
        var user = MakeUser(stamp: "current-stamp");
        var token = MakeRefreshToken(user, stamp: "old-stamp");
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        var service = CreateService();

        var result = await service.Refresh(token.Token, CancellationToken.None);

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task Refresh_SecurityStampMismatch_ShouldRevokeAllUserTokens() {
        var user = MakeUser(stamp: "current-stamp");
        var token = MakeRefreshToken(user, stamp: "old-stamp");
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        var service = CreateService();

        await service.Refresh(token.Token, CancellationToken.None);

        context.Verify(c => c.RefreshTokenRevokeAll(user.Id, It.IsAny<CancellationToken>()), Times.Once);
    }

    [TestMethod]
    public async Task Refresh_SecurityStampMismatch_ShouldNotIssueNewToken() {
        var user = MakeUser(stamp: "current-stamp");
        var token = MakeRefreshToken(user, stamp: "old-stamp");
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        var service = CreateService();

        await service.Refresh(token.Token, CancellationToken.None);

        context.Verify(c => c.RefreshTokenAdd(It.IsAny<ApplicationRefreshToken>()), Times.Never);
    }

    // -------------------------------------------------------------------------
    // Refresh — happy path
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task Refresh_ValidToken_ShouldReturnNewTokenPair() {
        var user = MakeUser();
        var token = MakeRefreshToken(user);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        var service = CreateService();

        var result = await service.Refresh(token.Token, CancellationToken.None);

        Assert.IsNotNull(result);
        Assert.AreEqual(FakeAccessToken, result!.AccessToken);
        Assert.IsFalse(string.IsNullOrEmpty(result.RefreshToken));
    }

    [TestMethod]
    public async Task Refresh_ValidToken_ShouldRevokeOldToken() {
        var user = MakeUser();
        var token = MakeRefreshToken(user);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        var service = CreateService();

        await service.Refresh(token.Token, CancellationToken.None);

        context.Verify(c => c.RefreshTokenRevoke(token), Times.Once);
    }

    [TestMethod]
    public async Task Refresh_ValidToken_ShouldPersistNewToken() {
        var user = MakeUser();
        var token = MakeRefreshToken(user);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        var service = CreateService();

        await service.Refresh(token.Token, CancellationToken.None);

        context.Verify(c => c.RefreshTokenAdd(It.IsAny<ApplicationRefreshToken>()), Times.Once);
    }

    [TestMethod]
    public async Task Refresh_ValidToken_NewRefreshTokenShouldCarryCurrentStamp() {
        var user = MakeUser(stamp: "stamp-v2");
        var token = MakeRefreshToken(user, stamp: "stamp-v2");
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        ApplicationRefreshToken? captured = null;
        context.Setup(c => c.RefreshTokenAdd(It.IsAny<ApplicationRefreshToken>()))
            .Callback<ApplicationRefreshToken>(t => captured = t);

        var service = CreateService();
        await service.Refresh(token.Token, CancellationToken.None);

        Assert.AreEqual("stamp-v2", captured?.SecurityStamp);
    }

    // -------------------------------------------------------------------------
    // Refresh — grace period (duplicate / simultaneous calls)
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task Refresh_CalledTwiceWithSameToken_ShouldReturnSameResult() {
        var user = MakeUser();
        var token = MakeRefreshToken(user);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        var service = CreateService();

        var first = await service.Refresh(token.Token, CancellationToken.None);
        var second = await service.Refresh(token.Token, CancellationToken.None);

        Assert.IsNotNull(first);
        Assert.IsNotNull(second);
        Assert.AreEqual(first!.RefreshToken, second!.RefreshToken);
    }

    [TestMethod]
    public async Task Refresh_CalledTwiceWithSameToken_ShouldOnlyRotateOnce() {
        var user = MakeUser();
        var token = MakeRefreshToken(user);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        context.Setup(c => c.UserFindRecord(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        var service = CreateService();

        await service.Refresh(token.Token, CancellationToken.None);
        await service.Refresh(token.Token, CancellationToken.None);

        // DB writes happen only on the first call; the second is served from cache
        context.Verify(c => c.RefreshTokenRevoke(It.IsAny<ApplicationRefreshToken>()), Times.Once);
        context.Verify(c => c.RefreshTokenAdd(It.IsAny<ApplicationRefreshToken>()), Times.Once);
    }

    // -------------------------------------------------------------------------
    // RevokeRefreshToken — guard clauses
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RevokeRefreshToken_EmptyToken_ShouldThrow() {
        var service = CreateService();

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.RevokeRefreshToken(string.Empty, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // RevokeRefreshToken — misuse
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RevokeRefreshToken_TokenNotFound_ShouldReturnFalse() {
        context.Setup(c => c.RefreshTokenFind(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((ApplicationRefreshToken?)null);
        var service = CreateService();

        var result = await service.RevokeRefreshToken("not-a-real-token", CancellationToken.None);

        Assert.IsFalse(result);
    }

    [TestMethod]
    public async Task RevokeRefreshToken_AlreadyRevoked_ShouldReturnFalse() {
        var user = MakeUser();
        var token = MakeRefreshToken(user, revoked: true);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        var service = CreateService();

        var result = await service.RevokeRefreshToken(token.Token, CancellationToken.None);

        Assert.IsFalse(result);
    }

    [TestMethod]
    public async Task RevokeRefreshToken_AlreadyRevoked_ShouldNotWriteToDb() {
        var user = MakeUser();
        var token = MakeRefreshToken(user, revoked: true);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        var service = CreateService();

        await service.RevokeRefreshToken(token.Token, CancellationToken.None);

        context.Verify(c => c.Complete(), Times.Never);
    }

    // -------------------------------------------------------------------------
    // RevokeRefreshToken — happy path
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task RevokeRefreshToken_ValidToken_ShouldReturnTrue() {
        var user = MakeUser();
        var token = MakeRefreshToken(user);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        var service = CreateService();

        var result = await service.RevokeRefreshToken(token.Token, CancellationToken.None);

        Assert.IsTrue(result);
    }

    [TestMethod]
    public async Task RevokeRefreshToken_ValidToken_ShouldCallRevoke() {
        var user = MakeUser();
        var token = MakeRefreshToken(user);
        context.Setup(c => c.RefreshTokenFind(token.Token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);
        var service = CreateService();

        await service.RevokeRefreshToken(token.Token, CancellationToken.None);

        context.Verify(c => c.RefreshTokenRevoke(token), Times.Once);
        context.Verify(c => c.Complete(), Times.Once);
    }

    // -------------------------------------------------------------------------
    // ReadUserIdFromExpiredToken
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ReadUserIdFromExpiredToken_NullToken_ShouldReturnNull() {
        var service = CreateService();

        var result = service.ReadUserIdFromExpiredToken(null!);

        Assert.IsNull(result);
    }

    [TestMethod]
    public void ReadUserIdFromExpiredToken_GarbageString_ShouldReturnNull() {
        var service = CreateService();

        var result = service.ReadUserIdFromExpiredToken("this-is-not-a-jwt");

        Assert.IsNull(result);
    }

    [TestMethod]
    public void ReadUserIdFromExpiredToken_ValidToken_ShouldReturnUserId() {
        var userId = Guid.NewGuid();
        var token = GenerateRealJwt(userId, expiryMinutes: 5);
        var service = CreateService();

        var result = service.ReadUserIdFromExpiredToken(token);

        Assert.AreEqual(userId, result);
    }

    [TestMethod]
    public void ReadUserIdFromExpiredToken_ExpiredToken_ShouldStillReturnUserId() {
        var userId = Guid.NewGuid();
        // Build a token with a past expiry directly
        var key = Convert.FromBase64String(config.JwtSettings.Secret);
        var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
        var expired = new JwtSecurityToken(
            config.JwtSettings.Issuer,
            config.JwtSettings.Audience,
            [new Claim(ClaimTypes.NameIdentifier, userId.ToString())],
            notBefore: DateTime.UtcNow.AddHours(-2),
            expires: DateTime.UtcNow.AddHours(-1),
            signingCredentials: credentials);
        var tokenString = new JwtSecurityTokenHandler().WriteToken(expired);

        var result = CreateService().ReadUserIdFromExpiredToken(tokenString);

        Assert.AreEqual(userId, result);
    }

    [TestMethod]
    public void ReadUserIdFromExpiredToken_TokenWithNoSubjectClaim_ShouldReturnNull() {
        // Token with no NameIdentifier claim
        var key = Convert.FromBase64String(config.JwtSettings.Secret);
        var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            config.JwtSettings.Issuer,
            config.JwtSettings.Audience,
            [new Claim(ClaimTypes.Email, "alice@example.com")],
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: credentials);
        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        var result = CreateService().ReadUserIdFromExpiredToken(tokenString);

        Assert.IsNull(result);
    }

    // -------------------------------------------------------------------------
    // IssuePreAuthToken — guard clauses
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task IssuePreAuthToken_NullContext_ShouldThrow() {
        var service = CreateService();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => service.IssuePreAuthToken(null!, CancellationToken.None));
    }

    // -------------------------------------------------------------------------
    // IssuePreAuthToken — token content
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task IssuePreAuthToken_ValidContext_ShouldReturnNonEmptyToken() {
        var ctx = MakeUserContext(MakeUser());
        var service = CreateService();

        var token = await service.IssuePreAuthToken(ctx, CancellationToken.None);

        Assert.IsFalse(string.IsNullOrEmpty(token));
    }

    [TestMethod]
    public async Task IssuePreAuthToken_Token_ShouldContainUserId() {
        var user = MakeUser();
        var ctx = MakeUserContext(user);
        var service = CreateService();

        var tokenString = await service.IssuePreAuthToken(ctx, CancellationToken.None);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);
        var subject = jwt.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
        Assert.AreEqual(user.Id.ToString(), subject);
    }

    [TestMethod]
    public async Task IssuePreAuthToken_Token_ShouldNotContainTenantOrRoleClaims() {
        var ctx = MakeUserContext(MakeUser());
        var service = CreateService();

        var tokenString = await service.IssuePreAuthToken(ctx, CancellationToken.None);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);
        Assert.IsFalse(jwt.Claims.Any(c => c.Type == N2ClaimTypes.TenantMembership),
            "Pre-auth token must not contain tenant claims");
        Assert.IsFalse(jwt.Claims.Any(c => c.Type == N2ClaimTypes.TenantRole),
            "Pre-auth token must not contain role claims");
    }

    [TestMethod]
    public async Task IssuePreAuthToken_Token_ShouldExpireAccordingToSettings() {
        var ctx = MakeUserContext(MakeUser());
        var service = CreateService();
        var before = DateTime.UtcNow;

        var tokenString = await service.IssuePreAuthToken(ctx, CancellationToken.None);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);
        var expectedExpiry = before.AddMinutes(config.JwtSettings.PreAuthTokenExpirationInMinutes);
        // Allow a few seconds of tolerance for test execution time
        Assert.IsTrue(jwt.ValidTo >= before.AddMinutes(config.JwtSettings.PreAuthTokenExpirationInMinutes - 1));
        Assert.IsTrue(jwt.ValidTo <= expectedExpiry.AddSeconds(5));
    }

    // -------------------------------------------------------------------------
    // Logoff
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task Logoff_ShouldRevokeAllTokensForUser() {
        var userId = Guid.NewGuid();
        var service = CreateService();

        await service.Logoff(userId, CancellationToken.None);

        context.Verify(c => c.RefreshTokenRevokeAll(userId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [TestMethod]
    public async Task Logoff_ShouldPersistRevocations() {
        var userId = Guid.NewGuid();
        var service = CreateService();

        await service.Logoff(userId, CancellationToken.None);

        context.Verify(c => c.Complete(), Times.Once);
    }

    [TestMethod]
    public async Task Logoff_WithNoActiveTokens_ShouldStillSucceed() {
        // RevokeAll on a user with no tokens is a no-op — Complete still returns success
        var userId = Guid.NewGuid();
        var service = CreateService();

        var result = await service.Logoff(userId, CancellationToken.None);

        Assert.IsTrue(result);
    }
}
