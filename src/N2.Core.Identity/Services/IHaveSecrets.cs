using N2.Core.Identity.Models;

namespace N2.Core.Identity.Services;

/// <summary>
/// Implemented by managers whose entities can own <c>ApplicationSecret</c> records.
/// Provides a uniform way to obtain an <see cref="ISecretOwner"/> for use with <c>ISecretManager</c>.
/// </summary>
public interface IHaveSecrets {
    /// <summary>
    /// Returns the <see cref="ISecretOwner"/> for the entity identified by <paramref name="id"/>,
    /// or <c>null</c> if the entity does not exist.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when the entity exists but has no MFA secret configured.</exception>
    Task<ISecretOwner?> GetSecretOwner(Guid id, CancellationToken token);

    Task<ISecretManager> GetSecretManager(CancellationToken token);
}
