using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace N2.Core.Identity.Migrations
{
    /// <inheritdoc />
    public partial class AddTenantTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);
            migrationBuilder.CreateTable(
                name: "Tenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(nullable: false),
                    Name = table.Column<string>(maxLength: 100, nullable: true),
                    NormalizedName = table.Column<string>(maxLength: 100, nullable: true),
                    Address = table.Column<string>(maxLength: 1000, nullable: true),
                    AdminEmail = table.Column<string>(maxLength: 100, nullable: true),
                    NormalizedEmail = table.Column<string>(maxLength: 100, nullable: true),
                    ContactInfo = table.Column<string>(maxLength: 1000, nullable: true),
                    ImagePath = table.Column<string>(maxLength: 100, nullable: true),
                    IsLocked = table.Column<bool>(nullable: false),
                    IsRemoved = table.Column<bool>(nullable: false),
                    IsHidden = table.Column<bool>(nullable: false),
                    UserLimit = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tenants", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserTenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(nullable: false),
                    ApplicationUserId = table.Column<Guid>(nullable: false),
                    ApplicationTenantId = table.Column<Guid>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserTenants", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserTenants_AspNetUsers_ApplicationUserId",
                        column: x => x.ApplicationUserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserTenants_Tenants_ApplicationTenantId",
                        column: x => x.ApplicationTenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_UserTenants_ApplicationTenantId",
                table: "UserTenants",
                column: "ApplicationTenantId");

            migrationBuilder.CreateIndex(
                name: "IX_UserTenants_ApplicationUserId",
                table: "UserTenants",
                column: "ApplicationUserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            ArgumentNullException.ThrowIfNull(migrationBuilder);
            migrationBuilder.DropTable(
                name: "UserTenants");

            migrationBuilder.DropTable(
                name: "Tenants");
        }
    }
}
