using N2.Core.Entity;

namespace N2.Core.Identity.Services;

/// <summary>
/// Receives changelog entries emitted by library services.
/// </summary>
/// <remarks>
/// Register a concrete implementation in the host's DI container.
/// What happens to each entry — database persistence, forwarding to a message bus,
/// writing to a file — is entirely the host's concern.
/// When not registered, library services operate without emitting audit entries.
/// </remarks>
public interface IChangeLogWriter {
    /// <summary>Adds a changelog entry.</summary>
    void Add(IChangeLog entry);
}
