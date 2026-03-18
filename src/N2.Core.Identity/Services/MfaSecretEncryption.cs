using Microsoft.Extensions.Logging;

using System.Security.Cryptography;
using System.Text;

namespace N2.Core.Identity.Services;

/// <summary>
/// AES-256-GCM encryption for MFA secrets stored in the database.
/// </summary>
/// <remarks>
/// Stored format: <c>v1:{Base64(nonce || tag || ciphertext)}</c>
/// <list type="bullet">
///   <item>The <c>v1:</c> prefix versions the format for future algorithm changes.</item>
///   <item>Legacy plaintext values (no prefix) are passed through unchanged so
///         existing rows are readable until they are re-encrypted.</item>
///   <item>Decryption tries the primary key first, then the secondary key to
///         support zero-downtime key rotation via <c>MfaTokenSecret2</c>.</item>
/// </list>
/// </remarks>
internal static class MfaSecretEncryption {
    private const string Prefix = "v1:";
    private const int NonceSize = 12; // AES-GCM recommended nonce size (bytes)
    private const int TagSize = 16;   // AES-GCM authentication tag size (bytes)
    private const int MinKeyBytes = 32;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with AES-256-GCM using the supplied Base64 key.
    /// </summary>
    internal static string Encrypt(string plaintext, string base64Key) {
        ArgumentException.ThrowIfNullOrEmpty(plaintext);

        if (string.IsNullOrEmpty(base64Key)) {
            throw new InvalidOperationException(
                "MfaTokenSecret is not configured. " +
                "Generate a key with: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))");
        }

        var key = Convert.FromBase64String(base64Key);
        if (key.Length < MinKeyBytes) {
            throw new InvalidOperationException(
                $"MfaTokenSecret must be at least {MinKeyBytes} bytes (256 bits). Current: {key.Length} bytes.");
        }

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        // Pack nonce || tag || ciphertext into one Base64 blob
        var combined = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(combined, 0);
        tag.CopyTo(combined, NonceSize);
        ciphertext.CopyTo(combined, NonceSize + TagSize);

        return Prefix + Convert.ToBase64String(combined);
    }

    /// <summary>
    /// Decrypts a value produced by <see cref="Encrypt"/>.
    /// Tries <paramref name="primaryBase64Key"/> first, then <paramref name="secondaryBase64Key"/>
    /// to support key rollover.
    /// Returns the original value unchanged for legacy plaintext secrets (no <c>v1:</c> prefix).
    /// Returns <see langword="null"/> if both keys fail authentication.
    /// </summary>
    /// <remarks>
    /// <b>Warning:</b> the plaintext passthrough path exists only for backward compatibility with rows
    /// that were stored before encryption was introduced. These rows should be re-encrypted at the
    /// earliest opportunity. The passthrough will be removed in a future version.
    /// </remarks>
    internal static string? TryDecrypt(string? encrypted, string primaryBase64Key, string? secondaryBase64Key = null, ILogger? logger = null) {
        if (string.IsNullOrEmpty(encrypted)) {
            return encrypted;
        }

#pragma warning disable CA1848 // improve performance for logging
        // Legacy plaintext passthrough — value was stored before encryption was introduced.
        // SECURITY: this path must be removed once all legacy rows have been re-encrypted.
        if (!encrypted.StartsWith(Prefix, StringComparison.Ordinal)) {
            logger?.LogCritical(
                "MfaSecretEncryption: plaintext passthrough triggered for a secret that has no v1: prefix. " +
                "This row was stored before encryption was introduced and must be re-encrypted immediately. " +
                "The plaintext passthrough will be removed in a future version.");
            return encrypted;
#pragma warning restore CA1848
        }

        var combined = Convert.FromBase64String(encrypted[Prefix.Length..]);
        if (combined.Length < NonceSize + TagSize) {
            return null;
        }

        var nonce = combined[..NonceSize];
        var tag = combined[NonceSize..(NonceSize + TagSize)];
        var ciphertext = combined[(NonceSize + TagSize)..];
        var plaintext = new byte[ciphertext.Length];

        if (!string.IsNullOrEmpty(primaryBase64Key) &&
            TryDecryptWithKey(Convert.FromBase64String(primaryBase64Key), nonce, ciphertext, tag, plaintext)) {
            return Encoding.UTF8.GetString(plaintext);
        }

        if (!string.IsNullOrEmpty(secondaryBase64Key) &&
            TryDecryptWithKey(Convert.FromBase64String(secondaryBase64Key), nonce, ciphertext, tag, plaintext)) {
            return Encoding.UTF8.GetString(plaintext);
        }

        return null;
    }

    private static bool TryDecryptWithKey(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] output) {
        try {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, output);
            return true;
        } catch (CryptographicException) {
            return false;
        }
    }
}
