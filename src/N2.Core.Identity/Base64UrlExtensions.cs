namespace N2.Core.Identity;

internal static class Base64UrlExtensions {
    /// <summary>Encodes bytes as base64url (no padding).</summary>
    internal static string Encode(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    /// <summary>
    /// Decodes a base64url string. Returns null on invalid input.
    /// </summary>
    internal static byte[]? TryDecode(string s) {
#pragma warning disable CA1031 // Do not catch general exception types (intentional return of null when conversion fails).
        try {
            s = s.Replace('-', '+').Replace('_', '/');
            s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
            return Convert.FromBase64String(s);
        } catch { return null; }
#pragma warning restore CA1031 // Do not catch general exception types
    }
}
