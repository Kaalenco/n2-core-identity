using N2.Core.Commands;
using N2.Core.Identity.Data;

using System.Diagnostics.CodeAnalysis;

namespace N2.Core.Identity.Services;

public interface IApplicationManager : IHaveSecrets {
    // -------------------------------------------------------------------------
    // ApplicationDefinition lifecycle
    // -------------------------------------------------------------------------

    /// <summary>Creates a new application.</summary>
    /// <param name="tenantId">The tenant to which the application belongs.</param>
    /// <param name="application">The application to create.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<ICommandResponse> Create(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken ct);

    /// <summary>Deletes a tenant and removes all user-tenant associations.</summary>
    /// <param name="tenantId">The tenant to which the application belongs.</param>
    /// <param name="application">The application to delete.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<ICommandResponse> Delete(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken ct);

    /// <summary>Updates mutable tenant properties (name, contact info, image path, etc.).</summary>
    /// <param name="tenantId">The tenant to which the application belongs.</param>
    /// <param name="application">The application to modify (only modifyable properties are changed).</param>
    /// <param name="ct">Cancellation token.</param>
    Task<ICommandResponse> Update(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken ct);

    // -------------------------------------------------------------------------
    // ApplicationDefinition lookup
    // -------------------------------------------------------------------------

    /// <summary>Finds an application by its unique identifier within a tenant.</summary>
    Task<ApplicationDefinition?> FindById(Guid tenantId, Guid applicationId, CancellationToken ct);

    /// <summary>Finds an application by name within a tenant. The value is normalised internally before lookup.</summary>
    Task<ApplicationDefinition?> FindByName(Guid tenantId, string name, CancellationToken ct);

    /// <summary>Returns a select list of all applications belonging to the given tenant, suitable for UI rendering.</summary>
    Task<SelectItemList<HtmlString>> GetApplicationGetSelectList(Guid tenantId, CancellationToken ct);

    // -------------------------------------------------------------------------
    // ApplicationDefinition status
    // -------------------------------------------------------------------------

    /// <summary>Locks an application, preventing all its users from signing in.</summary>
    Task<ICommandResponse> Lock(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken ct);
    /// <summary>Unlocks a previously locked application.</summary>
    Task<ICommandResponse> Unlock(Guid tenantId, [NotNull] ApplicationDefinition application, CancellationToken ct);

}

