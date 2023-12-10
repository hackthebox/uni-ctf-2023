using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Nexus_Void.Helpers;
using Nexus_Void.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Nexus_Void.Migrations;

namespace Nexus_Void.Controllers
{
    public class HomeController : Controller
    {
        private readonly DatabaseContext _db;
        private readonly IConfiguration _configuration;

        public HomeController(DatabaseContext db, IConfiguration configuration)
        {
            _db = db;
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Index()
        {

            ViewData["username"] = HttpContext.Items["username"];

            string sqlQuery = "SELECT * FROM Products";
            List<ProductModel> products = _db.Products.FromSqlRaw(sqlQuery).ToList<ProductModel>();

            return View(products);
        }

        [HttpGet]
        public IActionResult Wishlist()
        {
            string ID = HttpContext.Items["ID"].ToString();

            string sqlQueryGetWishlist = $"SELECT * from Wishlist WHERE ID='{ID}'";
            var wishlist = _db.Wishlist.FromSqlRaw(sqlQueryGetWishlist).FirstOrDefault();


            if (wishlist != null && !string.IsNullOrEmpty(wishlist.data))
            {
                List<ProductModel> products = SerializeHelper.Deserialize(wishlist.data);
                return View(products);

            }
            else
            {
                List<ProductModel> products = null;
                return View(products);

            }

        }

        [HttpPost]
        public IActionResult Wishlist(string name, string sellerName)
        {
            string ID = HttpContext.Items["ID"].ToString();

            string sqlQueryGetWishlist = $"SELECT * from Wishlist WHERE ID={ID}";
            var wishlist = _db.Wishlist.FromSqlRaw(sqlQueryGetWishlist).FirstOrDefault();

            string sqlQueryProduct = $"SELECT * from Products WHERE name='{name}' AND sellerName='{sellerName}'";
            var product = _db.Products.FromSqlRaw(sqlQueryProduct).FirstOrDefault();

            if(!string.IsNullOrEmpty(product.name))
            {
                if (wishlist != null && !string.IsNullOrEmpty(wishlist.data))
                {

                    List<ProductModel> products = SerializeHelper.Deserialize(wishlist.data);
                    ProductModel result = products.Find(x => x.name == product.name);

                    if (result != null)
                    {
                        return Content("Product already exists");
                    }

                    products.Add(product);

                    string serializedData = SerializeHelper.Serialize(products);

                    string sqlQueryAddWishlist = $"UPDATE Wishlist SET data='{serializedData}' WHERE ID={ID}";

                    _db.Database.ExecuteSqlRaw(sqlQueryAddWishlist);

                }
                else
                {
                    string username = HttpContext.Items["username"].ToString();

                    List<ProductModel> wishListProducts = new List<ProductModel>();

                    wishListProducts.Add(product);

                    string serializedData = SerializeHelper.Serialize(wishListProducts);

                    string sqlQueryAddWishlist = $"INSERT INTO Wishlist(ID, username, data) VALUES({ID},'{username}', '{serializedData}')";

                    _db.Database.ExecuteSqlRaw(sqlQueryAddWishlist);
                }

                return Content("Added");
            }

            return Content("Invalid");
        }

        [HttpGet]
        public IActionResult Setting()
        {
            ViewData["username"] = HttpContext.Items["username"];
            UserModel model = new UserModel();
            return View(model);
        }

        [HttpPost]
        public IActionResult Setting(UserModel user)
        {
            string ID = HttpContext.Items["ID"].ToString();
            JWTHelper jwt = new JWTHelper(_configuration);

            string jwtToken = jwt.GenerateJwtToken(user.username, ID);

            string sqlQuery = $"UPDATE Users SET username='{user.username}' WHERE ID={ID}";
            _db.Database.ExecuteSqlRaw(sqlQuery);

            Response.Cookies.Append("Token", jwtToken);

            ViewData["Message"] = "Profile updated!";
            ViewData["username"] = user.username;

            return View();
        }

        [HttpPost]
        public IActionResult WishlistRemove(string name, string sellerName)
        {
            string ID = HttpContext.Items["ID"].ToString();

            string sqlQueryGetWishlist = $"SELECT * from Wishlist WHERE ID='{ID}'";
            var wishlist = _db.Wishlist.FromSqlRaw(sqlQueryGetWishlist).FirstOrDefault();

            List<ProductModel> products = SerializeHelper.Deserialize(wishlist.data);

            ProductModel result = products.Find(x => x.name == name);

            products.Remove(result);

            string serializedData = SerializeHelper.Serialize(products);

            string sqlQueryAddWishlist = $"UPDATE Wishlist SET data='{serializedData}' WHERE ID='{ID}'";

            _db.Database.ExecuteSqlRaw(sqlQueryAddWishlist);

            return RedirectToAction("Home", "Wishlist");
        }

        [HttpGet]
        public void Logout() 
        {
            Response.Cookies.Delete("Token");
            Response.Redirect("/");
        }


        [Route("/uptime")]
        [HttpGet]
        public IActionResult Uptime()
        {
            StatusCheckHelper statusCheckHelper = new StatusCheckHelper();
            statusCheckHelper.command = "uptime";

            return Content(statusCheckHelper.output);
        }

        [Route("/health")]
        [HttpGet]
        public IActionResult Health()
        {
            return Content("OK");
        }

        [Route("/status")]
        [HttpGet]
        public IActionResult Status()
        {
            StatusCheckHelper statusCheckHelper = new StatusCheckHelper();

            statusCheckHelper.command = "bash /tmp/cpu.sh";
            string cpuUsage = statusCheckHelper.output;

            statusCheckHelper.command = "bash /tmp/mem.sh";
            string memoryUsage = statusCheckHelper.output;

            statusCheckHelper.command = "bash /tmp/disk.sh";
            string diskUsage = statusCheckHelper.output;

            return Content($"CPU Usage: {cpuUsage}\nMemory Usage: {memoryUsage}\nDisk Space: {diskUsage}");
        }

    }
}
