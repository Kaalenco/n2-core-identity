using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace N2.Core.Identity.Migrations
{
    /// <inheritdoc />
    public partial class AddSaltToSecretsDataset : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);

            migrationBuilder.AddColumn<byte[]>(
                name: "EncryptionSalt",
                table: "ApplicationSecrets",
                maxLength: 64,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);

            migrationBuilder.DropColumn(
                name: "EncryptionSalt",
                table: "ApplicationSecrets");
        }
    }
}
