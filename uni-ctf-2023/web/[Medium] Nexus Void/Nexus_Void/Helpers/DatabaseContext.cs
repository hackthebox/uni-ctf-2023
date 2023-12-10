using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Nexus_Void.Models;

namespace Nexus_Void.Helpers
{
    public class DatabaseContext : DbContext
    {
        public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options)
        {

        }

        public DbSet<UserModel> Users { get; set; }
        public DbSet<ProductModel> Products { get; set; }
        public DbSet<WishlistModel> Wishlist { get; set; }



        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            List<ProductModel> productsList = new List<ProductModel>();

            productsList.Add(new ProductModel { ID = 1, backdropImage = "/images/back1.png", currentBid = "45 ETH", endingIn = "10 Days", image = "/images/weapon.png", name = "Shadowcaster MK VI", sellerName = "Xclow3n" });
            productsList.Add(new ProductModel { ID = 2, backdropImage = "/images/back2.png", currentBid = "25 ETH", endingIn = "2 Days", image = "/images/blade.png", name = "Vortex Edgeblade", sellerName = "Xclow3n" });
            productsList.Add(new ProductModel { ID = 3, backdropImage = "/images/back3.png", currentBid = "50 ETH", endingIn = "3 Days", image = "/images/hand.png", name = "TechSinergi Cyberlimb", sellerName = "Xclow3n" });
            productsList.Add(new ProductModel { ID = 4, backdropImage = "/images/back4.png", currentBid = "100 ETH", endingIn = "7 Days", image = "/images/grenade.png", name = "Serum XY Scourgecaster", sellerName = "Xclow3n" });
            productsList.Add(new ProductModel { ID = 5, backdropImage = "/images/back5.png", currentBid = "99 ETH", endingIn = "4 Days", image = "/images/something.png", name = "NeuroHack Cortex Gear", sellerName = "Xclow3n" });
            productsList.Add(new ProductModel { ID = 6, backdropImage = "/images/back6.png", currentBid = "1337 ETH", endingIn = "3 Days", image = "/images/breach.png", name = "NeuroLink Intrusion Node", sellerName = "Xclow3n" });

            modelBuilder.Entity<ProductModel>().HasData(productsList);
        }


    }
}

