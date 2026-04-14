using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace N2.Core.Identity.Migrations
{
    /// <inheritdoc />
    public partial class AddSecurityTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);
            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "RefreshTokens",
                maxLength: 36,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);
            migrationBuilder.DropColumn(
                name: "SecurityStamp",
                table: "RefreshTokens");
        }
    }
}
