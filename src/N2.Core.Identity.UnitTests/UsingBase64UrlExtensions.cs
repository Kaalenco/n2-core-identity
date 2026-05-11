using N2.Core.Identity;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public sealed class UsingBase64UrlExtensions
{
    // -------------------------------------------------------------------------
    // Encode
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Encode_EmptyBytes_ReturnsEmptyString()
    {
        string result = Base64UrlExtensions.Encode([]);
        Assert.AreEqual(string.Empty, result);
    }

    [TestMethod]
    public void Encode_DoesNotContainPlusOrSlash()
    {
        byte[] input = [0xFB, 0xFF, 0xFE, 0x3C, 0x9D];
        string result = Base64UrlExtensions.Encode(input);
        Assert.IsFalse(result.Contains('+'));
        Assert.IsFalse(result.Contains('/'));
    }

    [TestMethod]
    public void Encode_HasNoPaddingCharacters()
    {
        byte[] input = [1, 2, 3];
        string result = Base64UrlExtensions.Encode(input);
        Assert.IsFalse(result.Contains('='));
    }

    // -------------------------------------------------------------------------
    // TryDecode
    // -------------------------------------------------------------------------

    [TestMethod]
    public void TryDecode_InvalidInput_ReturnsNull()
    {
        byte[]? result = Base64UrlExtensions.TryDecode("!!!not-base64!!!");
        Assert.IsNull(result);
    }

    [TestMethod]
    public void TryDecode_EmptyString_ReturnsEmptyArray()
    {
        byte[]? result = Base64UrlExtensions.TryDecode(string.Empty);
        Assert.IsNotNull(result);
        Assert.AreEqual(0, result!.Length);
    }

    // -------------------------------------------------------------------------
    // Roundtrip
    // -------------------------------------------------------------------------

    [TestMethod]
    public void Roundtrip_EncodeThenDecode_YieldsOriginalBytes()
    {
        byte[] original = [10, 20, 30, 40, 50, 200, 250];
        string encoded = Base64UrlExtensions.Encode(original);
        byte[]? decoded = Base64UrlExtensions.TryDecode(encoded);
        CollectionAssert.AreEqual(original, decoded);
    }

    [TestMethod]
    public void Roundtrip_AllByteValues_RoundTripsCorrectly()
    {
        byte[] original = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        string encoded = Base64UrlExtensions.Encode(original);
        byte[]? decoded = Base64UrlExtensions.TryDecode(encoded);
        CollectionAssert.AreEqual(original, decoded);
    }
}
