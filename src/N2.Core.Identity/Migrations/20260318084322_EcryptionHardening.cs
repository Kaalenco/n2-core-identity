using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace N2.Core.Identity.Migrations
{
    /// <inheritdoc />
    public partial class EcryptionHardening : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);

            migrationBuilder.AlterColumn<string>(
                name: "MfaSecret",
                table: "Tenants",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldNullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "SecretKeyMaterial",
                table: "Tenants",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "MfaSecret",
                table: "AspNetUsers",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldNullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "SecretKeyMaterial",
                table: "AspNetUsers",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "MfaSecret",
                table: "Applications",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(128)",
                oldMaxLength: 128,
                oldNullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "SecretKeyMaterial",
                table: "Applications",
                maxLength: 32,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);

            migrationBuilder.DropColumn(
                name: "SecretKeyMaterial",
                table: "Tenants");

            migrationBuilder.DropColumn(
                name: "SecretKeyMaterial",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "SecretKeyMaterial",
                table: "Applications");

            migrationBuilder.AlterColumn<string>(
                name: "MfaSecret",
                table: "Tenants",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(256)",
                oldMaxLength: 256,
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "MfaSecret",
                table: "AspNetUsers",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(256)",
                oldMaxLength: 256,
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "MfaSecret",
                table: "Applications",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(256)",
                oldMaxLength: 256,
                oldNullable: true);
        }
    }
}
