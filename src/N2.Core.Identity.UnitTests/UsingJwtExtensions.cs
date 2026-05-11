using N2.Core.Identity;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public sealed class UsingJwtExtensions
{
    // -------------------------------------------------------------------------
    // HasLowEntropy
    // -------------------------------------------------------------------------

    [TestMethod]
    public void HasLowEntropy_NullKey_ReturnsTrue()
    {
        bool result = JwtExtensions.HasLowEntropy(null!);
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void HasLowEntropy_AllIdenticalBytes_ReturnsTrue()
    {
        byte[] key = Enumerable.Repeat((byte)0xAA, 32).ToArray();
        bool result = JwtExtensions.HasLowEntropy(key);
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void HasLowEntropy_HighlySequentialBytes_ReturnsTrue()
    {
        // 31 consecutive diffs of 1 → 31/31 = 100% sequential
        byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        bool result = JwtExtensions.HasLowEntropy(key);
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void HasLowEntropy_DiverseNonSequentialBytes_ReturnsFalse()
    {
        // i*37+11 mod 256: 32 distinct values, consecutive diffs ≠ 1
        byte[] key = Enumerable.Range(0, 32).Select(i => (byte)((i * 37 + 11) % 256)).ToArray();
        bool result = JwtExtensions.HasLowEntropy(key);
        Assert.IsFalse(result);
    }

    // -------------------------------------------------------------------------
    // TryConvertBase64String
    // -------------------------------------------------------------------------

    [TestMethod]
    public void TryConvertBase64String_ValidBase64_ReturnsTrue()
    {
        string base64 = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });
        bool result = base64.TryConvertBase64String(out var data);
        Assert.IsTrue(result);
        Assert.AreEqual(4, data.Length);
    }

    [TestMethod]
    public void TryConvertBase64String_InvalidChars_ReturnsFalse()
    {
        bool result = "not!base64@#".TryConvertBase64String(out _);
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void TryConvertBase64String_EmptyString_ReturnsFalse()
    {
        bool result = string.Empty.TryConvertBase64String(out _);
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void TryConvertBase64String_NotDivisibleByFour_ReturnsFalse()
    {
        bool result = "ABC".TryConvertBase64String(out _);
        Assert.IsFalse(result);
    }

    // -------------------------------------------------------------------------
    // GenerateSecureKey
    // -------------------------------------------------------------------------

    [TestMethod]
    public void GenerateSecureKey_DefaultLength_Returns32ByteBase64()
    {
        AuthenticationConfig config = new();
        string key = config.GenerateSecureKey();
        bool isValid = key.TryConvertBase64String(out var data);
        Assert.IsTrue(isValid);
        Assert.AreEqual(32, data.Length);
    }

    [TestMethod]
    public void GenerateSecureKey_NullConfig_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwtExtensions.GenerateSecureKey(null!));
    }

    [TestMethod]
    public void GenerateSecureKey_LengthBelowMinimum_ThrowsArgumentException()
    {
        AuthenticationConfig config = new();
        Assert.Throws<ArgumentException>(() => config.GenerateSecureKey(16));
    }

    [TestMethod]
    public void GenerateSecureKey_EachCallProducesDifferentKey()
    {
        AuthenticationConfig config = new();
        string key1 = config.GenerateSecureKey();
        string key2 = config.GenerateSecureKey();
        Assert.AreNotEqual(key1, key2);
    }
}
