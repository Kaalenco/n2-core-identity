using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests.Data;

[TestClass]
public sealed class WithApplicationRefreshToken
{
    // -------------------------------------------------------------------------
    // IsExpired
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsExpired_ExpiresInFuture_ReturnsFalse()
    {
        ApplicationRefreshToken token = new() { ExpiresAt = DateTime.UtcNow.AddHours(1) };
        Assert.IsFalse(token.IsExpired);
    }

    [TestMethod]
    public void IsExpired_ExpiredInPast_ReturnsTrue()
    {
        ApplicationRefreshToken token = new() { ExpiresAt = DateTime.UtcNow.AddHours(-1) };
        Assert.IsTrue(token.IsExpired);
    }

    // -------------------------------------------------------------------------
    // IsRevoked
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsRevoked_RevokedAtNull_ReturnsFalse()
    {
        ApplicationRefreshToken token = new() { ExpiresAt = DateTime.UtcNow.AddHours(1) };
        Assert.IsFalse(token.IsRevoked);
    }

    [TestMethod]
    public void IsRevoked_RevokedAtSet_ReturnsTrue()
    {
        ApplicationRefreshToken token = new()
        {
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            RevokedAt = DateTime.UtcNow.AddMinutes(-5)
        };
        Assert.IsTrue(token.IsRevoked);
    }

    // -------------------------------------------------------------------------
    // IsValid
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsValid_NotExpiredNotRevoked_ReturnsTrue()
    {
        ApplicationRefreshToken token = new() { ExpiresAt = DateTime.UtcNow.AddHours(1) };
        Assert.IsTrue(token.IsValid);
    }

    [TestMethod]
    public void IsValid_Expired_ReturnsFalse()
    {
        ApplicationRefreshToken token = new() { ExpiresAt = DateTime.UtcNow.AddHours(-1) };
        Assert.IsFalse(token.IsValid);
    }

    [TestMethod]
    public void IsValid_Revoked_ReturnsFalse()
    {
        ApplicationRefreshToken token = new()
        {
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            RevokedAt = DateTime.UtcNow
        };
        Assert.IsFalse(token.IsValid);
    }

    [TestMethod]
    public void IsValid_ExpiredAndRevoked_ReturnsFalse()
    {
        ApplicationRefreshToken token = new()
        {
            ExpiresAt = DateTime.UtcNow.AddHours(-1),
            RevokedAt = DateTime.UtcNow.AddHours(-2)
        };
        Assert.IsFalse(token.IsValid);
    }
}
