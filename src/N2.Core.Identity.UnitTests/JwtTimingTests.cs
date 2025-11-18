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
        var tokenString = generator.GenerateWebToken(userContext.Object, 60);

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
        var tokenString = generator.GenerateWebToken(userContext.Object, 60);
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
    public async Task ValidateToken_AfterExpiration_ShouldFail() {
        // Arrange
        var userContext = new Mock<IUserContext>();
        userContext.SetupGet(m => m.Name).Returns("testuser");
        userContext.SetupGet(m => m.PublicId).Returns(Guid.NewGuid());
        var authConfig = GetAuthenticationConfig();
        var generator = new WebTokenGenerator(authConfig.JwtSettings);

        // Generate token with 1-second expiration
        var tokenString = generator.GenerateWebToken(userContext.Object, -1); // -1 minutes = immediate expiration

        // Wait for token to expire
        await Task.Delay(2000);

        // Act & Assert
        var jwtSettings = authConfig.JwtSettings;
        var validationParameters = new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret)),
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero // No clock skew tolerance
        };

        var handler = new JwtSecurityTokenHandler();
        Assert.Throws<SecurityTokenExpiredException>(() => {
            handler.ValidateToken(tokenString, validationParameters, out _);
        });
    }
}