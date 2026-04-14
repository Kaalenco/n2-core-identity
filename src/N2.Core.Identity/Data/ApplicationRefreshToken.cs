using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace N2.Core.Identity.Data;

/// <summary>
/// A single-use refresh token issued alongside a JWT access token.
/// Consuming the token revokes it immediately; a new pair is issued on each successful refresh.
/// </summary>
public class ApplicationRefreshToken
{
    public Guid     Id        { get; set; } = Guid.NewGuid();
    public virtual Guid ApplicationUserId { get; set; }
    public virtual ApplicationUser ApplicationUser { get; set; } = null!;

    /// <summary>Opaque, cryptographically random Base64 string (64 bytes → 88 chars).</summary>
    public string   Token     { get; set; } = string.Empty;

    public DateTime IssuedAt  { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }

    public bool IsExpired => DateTime.UtcNow > ExpiresAt;
    public bool IsRevoked => RevokedAt.HasValue;
    public bool IsValid   => !IsExpired && !IsRevoked;

    public static ModelBuilder Configure(ModelBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var mb = builder.Entity<ApplicationRefreshToken>();
        mb.HasKey(r => r.Id);
        mb.HasOne(r => r.ApplicationUser)
            .WithMany(u => u.ApplicationRefreshToken)
            .HasForeignKey(r => r.ApplicationUserId)
            .OnDelete(DeleteBehavior.Cascade);
        mb.HasIndex(r => r.Token).IsUnique();
        mb.HasIndex(r => new { r.ApplicationUserId, r.ExpiresAt });
        return builder;
    }
}
