using Microsoft.IdentityModel.Tokens;

using Moq;

using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace N2.Core.Identity.UnitTests;
[TestClass]
public class JwtTimingTests : N2IdentityTestsBase {


    [TestMethod]
    public void GenerateToken_ShouldUseUtcTime() {
        // Arrange
        var userContext = new Mock<IUserContext>();
        userContext.SetupGet(m => m.Name).Returns("testuser");
        userContext.Setup(m => m.CurrentRoles()).Returns(["User"]);
        userContext.SetupGet(m => m.PublicId).Returns(Guid.NewGuid());

        var authConfig = GetAuthenticationConfig();
        var generator = new WebTokenGenerator(authConfig.JwtSettings);

        // Act
        var tokenString = generator.GenerateWebToken(userContext.Object, 10);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        // Token expiration should be based on UTC, not local time
        var expectedExpiration = DateTime.UtcNow.AddMinutes(10);
        var actualExpiration = token.ValidTo;

        // Allow 2 second tolerance for test execution time
        Assert.IsLessThan(2,
            Math.Abs((actualExpiration - expectedExpiration).TotalSeconds),
            $"Token expiration should be UTC-based. Expected: {expectedExpiration:u}, Actual: {actualExpiration:u}");
    }

    [TestMethod]
    public void GenerateToken_ShouldIncludeStandardClaims() {
        // Arrange
        var userContext = new Mock<IUserContext>();
        userContext.SetupGet(m => m.Name).Returns("testuser");
        userContext.SetupGet(m => m.PublicId).Returns(Guid.NewGuid());

        var authConfig = GetAuthenticationConfig();
        var generator = new WebTokenGenerator(authConfig.JwtSettings);

        // Act
        var tokenString = generator.GenerateWebToken(userContext.Object, 5);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        // Should include JTI (JWT ID)
        Assert.IsTrue(token.Claims.Any(c => c.Type == JwtRegisteredClaimNames.Jti),
            "Token should include 'jti' claim for revocation support");

        // Should include IAT (Issued At)
        Assert.IsTrue(token.Claims.Any(c => c.Type == JwtRegisteredClaimNames.Iat),
            "Token should include 'iat' claim for issued-at timestamp");

        // NotBefore should be set
        Assert.IsTrue(token.ValidFrom <= DateTime.UtcNow);
    }

    [TestMethod]
    public void GenerateToken_CrossTimezone_ShouldBeConsistent() {
        // Arrange
        var userContext = new Mock<IUserContext>();
        userContext.SetupGet(m => m.Name).Returns("testuser");
        userContext.SetupGet(m => m.PublicId).Returns(Guid.NewGuid());
        var authConfig = GetAuthenticationConfig();
        var generator = new WebTokenGenerator(authConfig.JwtSettings);

        // Act - Generate token
        var tokenString = generator.GenerateWebToken(userContext.Object, 5);
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        // Get expiration in different timezone representations
        var expirationUtc = token.ValidTo;
        var expirationLocal = token.ValidTo.ToLocalTime();

        // Assert - Converting back to UTC should give same result
        Assert.AreEqual(expirationUtc, expirationLocal.ToUniversalTime(),
            "Token expiration should be consistent across timezone conversions");
    }

    [TestMethod]
    public void GenerateRefreshToken_ShouldReturnValidBase64() {
        var authConfig = GetAuthenticationConfig();
        var generator = new WebTokenGenerator(authConfig.JwtSettings);

        var token = generator.GenerateRefreshToken();

        // 64 random bytes encode to 88 Base64 characters (with padding)
        Assert.IsNotNull(token);
        var decoded = Convert.FromBase64String(token); // throws if not valid Base64
        Assert.AreEqual(64, decoded.Length);
    }

    [TestMethod]
    public void GenerateRefreshToken_SuccessiveCallsShouldBeUnique() {
        var authConfig = GetAuthenticationConfig();
        var generator = new WebTokenGenerator(authConfig.JwtSettings);

        var tokens = Enumerable.Range(0, 20).Select(_ => generator.GenerateRefreshToken()).ToList();

        var uniqueCount = tokens.Distinct().Count();
        Assert.AreEqual(tokens.Count, uniqueCount, "All generated refresh tokens should be unique");
    }

    [TestMethod]
    public void RefreshTokenExpiry_WithJwtSettings_ShouldUseConfiguredExpiration() {
        var settings = new JwtSettings {
            Issuer = "test",
            Audience = "test",
            Secret = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
            RefreshTokenExpirationInMinutes = 720
        };
        var generator = new WebTokenGenerator(settings);
        var before = DateTime.UtcNow;

        var expiry = generator.RefreshTokenExpiry();

        var after = DateTime.UtcNow;
        Assert.IsTrue(expiry >= before.AddMinutes(720), "Expiry should be at least 720 minutes from now");
        Assert.IsTrue(expiry <= after.AddMinutes(720), "Expiry should not exceed 720 minutes from now");
    }

    [TestMethod]
    public void RefreshTokenExpiry_WithStringConstructor_ShouldUseDefaultExpiration() {
        var secret = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var generator = new WebTokenGenerator("issuer", "audience", secret);
        var before = DateTime.UtcNow;

        var expiry = generator.RefreshTokenExpiry();

        var after = DateTime.UtcNow;
        var expectedMinutes = JwtSettings.DefaultRefreshTokenExpirationInMinutes;
        Assert.IsTrue(expiry >= before.AddMinutes(expectedMinutes));
        Assert.IsTrue(expiry <= after.AddMinutes(expectedMinutes));
    }

    [TestMethod]
    public void RefreshTokenExpiry_ShouldBeInUtc() {
        var authConfig = GetAuthenticationConfig();
        var generator = new WebTokenGenerator(authConfig.JwtSettings);

        var expiry = generator.RefreshTokenExpiry();

        Assert.AreEqual(DateTimeKind.Utc, expiry.Kind, "Refresh token expiry should be UTC");
    }

    [TestMethod]
    public void ValidateToken_AfterExpiration_ShouldFail() {
        // Arrange — build an already-expired token directly so the test is instant
        // and independent of GenerateWebToken's minimum-timeout enforcement (1 minute).
        var authConfig = GetAuthenticationConfig();
        var jwtSettings = authConfig.JwtSettings;
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expiredToken = new JwtSecurityToken(
            issuer: jwtSettings.Issuer,
            audience: jwtSettings.Audience,
            expires: DateTime.UtcNow.AddMinutes(-2), // expired 2 minutes ago
            signingCredentials: credentials);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(expiredToken);

        // Act & Assert
        var validationParameters = new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        var handler = new JwtSecurityTokenHandler();
        Assert.Throws<SecurityTokenExpiredException>(() => {
            handler.ValidateToken(tokenString, validationParameters, out _);
        });
    }
}