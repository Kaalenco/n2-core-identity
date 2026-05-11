using Moq;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public sealed class WithWebTokenGenerator
{
    // i*37+11 mod 256 produces 32 diverse non-sequential bytes — passes ValidateKeySecurity
    private static readonly string ValidKey =
        Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)((i * 37 + 11) % 256)).ToArray());

    private static WebTokenGenerator Build() =>
        new("https://issuer.test", "https://audience.test", ValidKey);

    private static IUserContext MockUserContext()
    {
        var mock = new Mock<IUserContext>();
        mock.Setup(u => u.PublicId).Returns(Guid.NewGuid());
        mock.Setup(u => u.Name).Returns("testuser");
        mock.Setup(u => u.Email).Returns("test@example.com");
        mock.Setup(u => u.PhoneNumber).Returns(string.Empty);
        return mock.Object;
    }

    // -------------------------------------------------------------------------
    // GenerateWebToken
    // -------------------------------------------------------------------------

    [TestMethod]
    public void GenerateWebToken_NullContext_ThrowsArgumentNullException()
    {
        WebTokenGenerator gen = Build();
        Assert.Throws<ArgumentNullException>(() => gen.GenerateWebToken(null!, 5));
    }

    [TestMethod]
    public void GenerateWebToken_TimeoutAboveMaximum_ThrowsArgumentOutOfRangeException()
    {
        WebTokenGenerator gen = Build();
        Assert.Throws<ArgumentOutOfRangeException>(() => gen.GenerateWebToken(MockUserContext(), 16));
    }

    [TestMethod]
    public void GenerateWebToken_ValidContext_ProducesThreePartJwt()
    {
        WebTokenGenerator gen = Build();
        string token = gen.GenerateWebToken(MockUserContext(), 5);
        string[] parts = token.Split('.');
        Assert.AreEqual(3, parts.Length);
    }

    [TestMethod]
    public void GenerateWebToken_ZeroTimeout_UsesMinimumAndProducesToken()
    {
        WebTokenGenerator gen = Build();
        string token = gen.GenerateWebToken(MockUserContext(), 0);
        Assert.IsFalse(string.IsNullOrEmpty(token));
    }

    // -------------------------------------------------------------------------
    // GenerateRefreshToken
    // -------------------------------------------------------------------------

    [TestMethod]
    public void GenerateRefreshToken_ProducesValidBase64With64Bytes()
    {
        WebTokenGenerator gen = Build();
        string token = gen.GenerateRefreshToken();
        byte[] bytes = Convert.FromBase64String(token);
        Assert.AreEqual(64, bytes.Length);
    }

    [TestMethod]
    public void GenerateRefreshToken_EachCallProducesDifferentToken()
    {
        WebTokenGenerator gen = Build();
        string first = gen.GenerateRefreshToken();
        string second = gen.GenerateRefreshToken();
        Assert.AreNotEqual(first, second);
    }

    // -------------------------------------------------------------------------
    // RefreshTokenExpiry
    // -------------------------------------------------------------------------

    [TestMethod]
    public void RefreshTokenExpiry_ReturnsFutureDateTime()
    {
        WebTokenGenerator gen = Build();
        DateTime expiry = gen.RefreshTokenExpiry();
        Assert.IsTrue(expiry > DateTime.UtcNow);
    }
}
