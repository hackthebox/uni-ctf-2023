using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Nexus_Void.Migrations
{
    /// <inheritdoc />
    public partial class SeedProducts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "Products",
                columns: new[] { "ID", "backdropImage", "currentBid", "endingIn", "image", "name", "sellerName" },
                values: new object[,]
                {
                    { 1, "/images/back1.png", "45 ETH", "10 Days", "/images/weapon.png", "Shadowcaster MK VI", "Xclow3n" },
                    { 2, "/images/back2.png", "25 ETH", "2 Days", "/images/blade.png", "Vortex Edgeblade", "Xclow3n" },
                    { 3, "/images/back3.png", "50 ETH", "3 Days", "/images/hand.png", "TechSinergi Cyberlimb", "Xclow3n" },
                    { 4, "/images/back4.png", "100 ETH", "7 Days", "/images/grenade.png", "Serum XY Scourgecaster", "Xclow3n" },
                    { 5, "/images/back5.png", "99 ETH", "4 Days", "/images/something.png", "NeuroHack Cortex Gear", "Xclow3n" },
                    { 6, "/images/back6.png", "1337 ETH", "3 Days", "/images/breach.png", "NeuroLink Intrusion Node", "Xclow3n" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Products",
                keyColumn: "ID",
                keyValue: 1);

            migrationBuilder.DeleteData(
                table: "Products",
                keyColumn: "ID",
                keyValue: 2);

            migrationBuilder.DeleteData(
                table: "Products",
                keyColumn: "ID",
                keyValue: 3);

            migrationBuilder.DeleteData(
                table: "Products",
                keyColumn: "ID",
                keyValue: 4);

            migrationBuilder.DeleteData(
                table: "Products",
                keyColumn: "ID",
                keyValue: 5);

            migrationBuilder.DeleteData(
                table: "Products",
                keyColumn: "ID",
                keyValue: 6);
        }
    }
}
