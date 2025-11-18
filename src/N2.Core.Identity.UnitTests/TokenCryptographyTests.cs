using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using N2.Core.Commands;
using N2.Core.Identity.Services;

using System.Security.Cryptography;

namespace N2.Core.Identity.UnitTests;
[TestClass]
public class TokenCryptographyTests : N2IdentityTestsBase {

    [TestMethod]
    public async Task GenerateToken_ShouldUseHMAC_NotSHA384() {
        // Arrange
        var user = await CreateTestUser($"testuser-{Guid.NewGuid}", "P@ssw0rd123", MultiFactorType.Email);
        var userManager = GetUserManager();
        // Act
        var tokenResponse = await userManager.GenerateConfirmationTokenAsync(user, CancellationToken.None);

        // Assert
        Assert.IsTrue(tokenResponse.Status.IsSuccess());
        var token = tokenResponse.Value!;

        // HMAC-SHA256 produces 32-byte signature (44 chars in Base64)
        // Token format: {data}.{signature}
        var parts = token.Split('.');
        Assert.HasCount(2, parts);

        var signatureBytes = Convert.FromBase64String(parts[1]);
        Assert.HasCount(32, signatureBytes, "HMAC-SHA256 should produce 32-byte signature");
    }

    [TestMethod]
    public async Task ValidateToken_ValidToken_ShouldSucceed() {
        // Arrange
        var user = await CreateTestUser($"testuser-{Guid.NewGuid}", "P@ssw0rd123", MultiFactorType.Email);
        var userManager = GetUserManager();
        var tokenResponse = await userManager.GenerateConfirmationTokenAsync(user, CancellationToken.None);
        var token = tokenResponse.Value;

        // Act
        var result = await userManager.ValidateMultifactorAsync(user, token!, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    public async Task ValidateToken_TamperedToken_ShouldFail() {
        // Arrange
        var user = await CreateTestUser($"testuser-{Guid.NewGuid}", "P@ssw0rd123", MultiFactorType.Email);
        var userManager = GetUserManager();
        var tokenResponse = await userManager.GenerateConfirmationTokenAsync(user, CancellationToken.None);
        var token = tokenResponse.Value;

        // Tamper with the token
        var parts = token!.Split('.');
        var tamperedSignature = string.Concat(parts[1].AsSpan(0, parts[1].Length - 2), "XX");
        var tamperedToken = $"{parts[0]}.{tamperedSignature}";

        // Act
        var result = await userManager.ValidateMultifactorAsync(user, tamperedToken, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Unauthorized, result.Status);
    }

    [TestMethod]
    public void TokenSigningSecret_Missing_ShouldThrowException() {
        // Arrange - Create configuration without TokenSigningSecret
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Authentication:TwoFactorTotpName"] = "Test"
                // TokenSigningSecret intentionally missing
            })
            .Build();

        // Act & Assert
        var factory = ServiceProvider.GetRequiredService<IIdentityContextFactory>();
        var rateLimiter = ServiceProvider.GetRequiredService<IRateLimiter>();
        var pwdHash = ServiceProvider.GetRequiredService<IPasswordHasher<Data.ApplicationUser>>();
        var logger = ServiceProvider.GetRequiredService<ILogger<N2UserManager>>();
        Assert.Throws<InvalidOperationException>(() => {
            using var mgr = new N2UserManager(factory, config, rateLimiter, pwdHash, "testdb", logger);
        });

    }

    [TestMethod]
    public void TokenSigningSecret_TooShort_ShouldThrowException() {
        // Arrange - Create configuration with short secret
        var shortSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Authentication:TwoFactorTotpName"] = "Test",
                ["TokenSigningSecret"] = shortSecret
            })
            .Build();

        // Act & Assert
        var factory = ServiceProvider.GetRequiredService<IIdentityContextFactory>();
        var rateLimiter = ServiceProvider.GetRequiredService<IRateLimiter>();
        var pwdHash = ServiceProvider.GetRequiredService<IPasswordHasher<Data.ApplicationUser>>();
        var logger = ServiceProvider.GetRequiredService<ILogger<N2UserManager>>();
        Assert.Throws<InvalidOperationException>(() => {
            using var mgr = new N2UserManager(factory, config, rateLimiter, pwdHash, "testdb", logger);
        });
    }
}
