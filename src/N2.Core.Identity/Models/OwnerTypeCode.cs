using System.Security.Cryptography;
using System.Text;

namespace N2.Core.Identity.Models;

/// <summary>
/// Derives short, opaque type codes used as the <c>ownerTypeCode</c> segment of a secret token.
/// </summary>
/// <remarks>
/// The code is computed as the base64url encoding of the first 6 bytes of
/// <c>SHA-256(UTF8(typeName))</c>, yielding exactly 8 characters.
/// Using a hash instead of the raw type name prevents leaking class names from tokens
/// and keeps the segment length constant regardless of how long the type name is.
/// 6 bytes provides ~281 trillion possible codes, keeping collision probability negligible.
/// Pre-computed constants are provided for the built-in owner types.
/// </remarks>
public static class OwnerTypeCode {
    /// <summary>Pre-computed code for <c>ApplicationUser</c>.</summary>
    public static readonly string User = Compute("ApplicationUser");

    /// <summary>Pre-computed code for <c>ApplicationDefinition</c>.</summary>
    public static readonly string Application = Compute("ApplicationDefinition");

    /// <summary>Pre-computed code for <c>ApplicationTenant</c>.</summary>
    public static readonly string Tenant = Compute("ApplicationTenant");

    /// <summary>
    /// Derives the 8-character base64url type code for the given type name.
    /// </summary>
    /// <param name="typeName">The unqualified type name, e.g. <c>nameof(ApplicationUser)</c>.</param>
    /// <returns>An 8-character base64url string.</returns>
    public static string Compute(string typeName) {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(typeName));
        // 6 bytes → exactly 8 base64 characters with no padding
        return Convert.ToBase64String(hash[..6])
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
