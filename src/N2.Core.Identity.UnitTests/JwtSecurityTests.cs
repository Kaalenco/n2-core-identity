/*

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace N2.Core.Identity.UnitTests;
[TestClass]
public class JwtKeySecurityTests {

    [TestMethod]
    public void JwtConfiguration_KeyTooShort_ShouldThrowException() {
        // Arrange - Create configuration with 20-byte key
        var shortKey = new string('A', 20);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Jwt:Issuer"] = "test-issuer",
                ["Jwt:Audience"] = "test-audience",
                ["Jwt:Secret"] = shortKey
            })
            .Build();

        var services = new ServiceCollection();

        // Act - Should throw
        Assert.Throws<ArgumentException>(() => {
            services.AddJwtConfigurationFromFile(config);
        });
    }

    [TestMethod]
    public void JwtConfiguration_ValidKey_ShouldSucceed() {
        // Arrange - Create configuration with 32-byte key
        var validKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Jwt:Issuer"] = "test-issuer",
                ["Jwt:Audience"] = "test-audience",
                ["Jwt:Secret"] = validKey
            })
            .Build();

        var services = new ServiceCollection();

        // Act
        services.AddJwtConfigurationFromFile(config);

        // Assert
        var provider = services.BuildServiceProvider();
        var jwtSettings = provider.GetRequiredService<JwtSettings>();
        Assert.IsNotNull(jwtSettings);
        Assert.AreEqual(validKey, jwtSettings.Secret);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void GenerateToken_WeakKey_ShouldThrowException() {
        // Arrange - Weak key with low entropy
        var weakKey = "password123456781234567812345678"; // 32 chars but low entropy
        var jwtSettings = new JwtSettings {
            Issuer = "test",
            Audience = "test",
            Secret = weakKey
        };

        var generator = new WebTokenGenerator();
        var claims = new List<Claim> { new Claim(ClaimTypes.Name, "test") };

        // Act - Should throw due to low entropy
        generator.Generate(claims, 60, jwtSettings);
    }

    [TestMethod]
    public void GenerateSecureKey_ShouldMeetRequirements() {
        // Act
        var key = JwtExtensions.GenerateSecureJwtKey();

        // Assert
        var keyBytes = Convert.FromBase64String(key);
        Assert.IsTrue(keyBytes.Length >= 32, "Generated key should be at least 32 bytes");

        // Check entropy - should have good distribution
        var uniqueBytes = keyBytes.Distinct().Count();
        var entropyRatio = (double)uniqueBytes / keyBytes.Length;
        Assert.IsTrue(entropyRatio > 0.8, "Generated key should have high entropy");
    }

    [TestMethod]
    public void KeyLengthValidation_Base64Encoded_ShouldCalculateCorrectly() {
        // Arrange - 32 bytes = 44 Base64 characters (with padding)
        var keyBytes = RandomNumberGenerator.GetBytes(32);
        var base64Key = Convert.ToBase64String(keyBytes);

        // Act
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string> {
                ["Jwt:Issuer"] = "test",
                ["Jwt:Audience"] = "test",
                ["Jwt:Secret"] = base64Key
            })
            .Build();

        var services = new ServiceCollection();
        services.AddJwtConfigurationFromFile(config);

        // Assert - Should not throw
        var provider = services.BuildServiceProvider();
        var jwtSettings = provider.GetRequiredService<JwtSettings>();
        Assert.IsNotNull(jwtSettings);
    }
}

*/