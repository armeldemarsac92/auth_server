using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tdev702.Auth.Migrations
{
    /// <inheritdoc />
    public partial class UserProfilePicture : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ProfilePicture",
                schema: "auth",
                table: "AspNetUsers",
                type: "character varying(50)",
                maxLength: 50,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ProfilePicture",
                schema: "auth",
                table: "AspNetUsers");
        }
    }
}
