using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Prevents concurrent EF migrations from racing on the same database.
/// MySQL has no transactional DDL, so two simultaneous MigrateAsync calls that both
/// read an empty __EFMigrationsHistory will both try to CREATE TABLE and the second
/// one fails. The gate serialises the first call per connection string and skips
/// subsequent ones because EF is idempotent once the history table is populated.
/// </summary>
internal static class IntegrationMigrationGate {
    private static readonly SemaphoreSlim Lock = new(1, 1);
    private static readonly HashSet<string> Migrated = [];

    internal static async Task EnsureMigratedAsync(DatabaseFacade database) {
        var key = database.GetConnectionString() ?? string.Empty;

        if (Migrated.Contains(key))
            return;

        await Lock.WaitAsync();
        try {
            if (!Migrated.Contains(key)) {
                await database.MigrateAsync();
                Migrated.Add(key);
            }
        } finally {
            Lock.Release();
        }
    }
}
