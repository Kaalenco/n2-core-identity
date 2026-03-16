using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace N2.Core.Identity.Migrations
{
    /// <inheritdoc />
    public partial class AddSecretsToDbContext : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);
            migrationBuilder.AddColumn<string>(
                name: "MfaSecret",
                table: "Tenants",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "MfaSecret",
                table: "Applications",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "NormalizedName",
                table: "Applications",
                maxLength: 100,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "ApplicationSecrets",
                columns: table => new
                {
                    Id = table.Column<Guid>(nullable: false),
                    ReferenceId = table.Column<Guid>(nullable: false),
                    ReferenceType = table.Column<string>(nullable: false),
                    Name = table.Column<string>(maxLength: 100, nullable: true),
                    NormalizedName = table.Column<string>(maxLength: 100, nullable: true),
                    HashedToken = table.Column<string>(maxLength: 256, nullable: false),
                    Expiration = table.Column<DateTime>(nullable: true),
                    Description = table.Column<string>(maxLength: 1000, nullable: true),
                    Policies = table.Column<string>(maxLength: 1000, nullable: true),
                    Secret = table.Column<byte[]>(maxLength: 4000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApplicationSecrets", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);
            migrationBuilder.DropTable(
                name: "ApplicationSecrets");

            migrationBuilder.DropColumn(
                name: "MfaSecret",
                table: "Tenants");

            migrationBuilder.DropColumn(
                name: "MfaSecret",
                table: "Applications");

            migrationBuilder.DropColumn(
                name: "NormalizedName",
                table: "Applications");
        }
    }
}
