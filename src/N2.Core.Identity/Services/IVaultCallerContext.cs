namespace N2.Core.Identity.Services;

/// <summary>
/// Provides the identity of the authenticated caller for the current operation.
/// </summary>
/// <remarks>
/// Register a scoped implementation in the host's DI container, populated by
/// authentication middleware (e.g. from a verified client certificate or JWT claims).
/// When not registered, changelog entries are authored as <c>Guid.Empty / "system"</c>.
/// </remarks>
public interface IVaultCallerContext {
    /// <summary>Unique identifier of the authenticated caller.</summary>
    Guid CallerId { get; }

    /// <summary>Display name of the authenticated caller.</summary>
    string CallerName { get; }
}
