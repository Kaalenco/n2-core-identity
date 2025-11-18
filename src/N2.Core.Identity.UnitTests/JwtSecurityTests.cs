

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using Moq;

using System.Security.Cryptography;

namespace N2.Core.Identity.UnitTests;
[TestClass]
public class JwtKeySecurityTests {

    [TestMethod]
    public void JwtConfiguration_KeyTooShort_ShouldThrowException() {
        // Arrange - Create configuration with 20-byte key
        var shortKey = new string('A', 20);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["AuthenticationConfig:JwtSettings:Issuer"] = "test-issuer",
                ["AuthenticationConfig:JwtSettings:Audience"] = "test-audience",
                ["AuthenticationConfig:JwtSettings:Secret"] = shortKey
            })
            .Build();

        IServiceCollection services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);

        // Act - Should throw
        Assert.Throws<ArgumentException>(() => {
            services.AddJwtBearerAuthentication(config);
        });
    }

    [TestMethod]
    public void JwtConfiguration_ValidKey_ShouldSucceed() {
        // Arrange - Create configuration with 32-byte key
        var validKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["AuthenticationConfig:JwtSettings:Issuer"] = "test-issuer",
                ["AuthenticationConfig:JwtSettings:Audience"] = "test-audience",
                ["AuthenticationConfig:JwtSettings:Secret"] = validKey
            })
            .Build();

        var services = new ServiceCollection();

        // Act
        services.AddJwtBearerAuthentication(config);

        // Assert
        var provider = services.BuildServiceProvider();
        var jwtSettings = provider.GetRequiredService<AuthenticationConfig>();
        Assert.IsNotNull(jwtSettings);
        Assert.AreEqual(validKey, jwtSettings.JwtSettings.Secret);
    }

    [TestMethod]
    public void GenerateToken_WeakKey_ShouldThrowException() {
        // Arrange - Weak key with low entropy
        var weakKey = "password123456781234567812345678"; // 32 chars but low entropy
        var jwtSettings = new JwtSettings {
            Issuer = "test",
            Audience = "test",
            Secret = weakKey
        };

        var generator = new WebTokenGenerator(jwtSettings);
        var userMock = new Mock<IUserContext>();
        userMock.SetupGet(m => m.Name).Returns("test");

        // Act - Should throw due to low entropy
        Assert.Throws<ArgumentException>(() => {
            generator.GenerateWebToken(userMock.Object, 10);
        });
    }

    [TestMethod]
    public void GenerateSecureKey_ShouldMeetRequirements() {
        // Act
        var auth = new AuthenticationConfig();
        var key = auth.GenerateSecureKey();

        // Assert
        var keyBytes = Convert.FromBase64String(key);
        Assert.IsGreaterThanOrEqualTo(32, keyBytes.Length, "Generated key should be at least 32 bytes");

        // Check entropy - should have good distribution
        var uniqueBytes = keyBytes.Distinct().Count();
        var entropyRatio = (double)uniqueBytes / keyBytes.Length;
        Assert.IsGreaterThan(0.8, entropyRatio, "Generated key should have high entropy");
    }

    [TestMethod]
    public void KeyLengthValidation_Base64Encoded_ShouldCalculateCorrectly() {
        // Arrange - 32 bytes = 44 Base64 characters (with padding)
        var keyBytes = RandomNumberGenerator.GetBytes(32);
        var base64Key = Convert.ToBase64String(keyBytes);

        // Act
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["AuthenticationConfig:JwtSettings:Issuer"] = "test",
                ["AuthenticationConfig:JwtSettings:Audience"] = "test",
                ["AuthenticationConfig:JwtSettings:Secret"] = base64Key
            })
            .Build();

        var services = new ServiceCollection();
        services.AddJwtBearerAuthentication(config);

        // Assert - Should not throw
        var provider = services.BuildServiceProvider();
        var authSettings = provider.GetRequiredService<AuthenticationConfig>();
        Assert.IsNotNull(authSettings.JwtSettings);
    }
}

