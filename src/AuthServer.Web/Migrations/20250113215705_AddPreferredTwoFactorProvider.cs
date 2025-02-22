using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tdev702.Auth.Migrations
{
    /// <inheritdoc />
    public partial class AddPreferredTwoFactorProvider : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "PreferredTwoFactorProvider",
                schema: "auth",
                table: "AspNetUsers",
                type: "integer",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PreferredTwoFactorProvider",
                schema: "auth",
                table: "AspNetUsers");
        }
    }
}
