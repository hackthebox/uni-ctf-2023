using System.Diagnostics;
using System.Runtime.InteropServices.JavaScript;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Nexus_Void.Helpers;
using Nexus_Void.Models;

namespace Nexus_Void.Controllers;

public class LoginController : Controller
{
    private readonly ILogger<LoginController> _logger;
    private readonly DatabaseContext _db;
    private readonly IConfiguration _configuration;

    public LoginController(ILogger<LoginController> logger, DatabaseContext db, IConfiguration configuration)
    {
        _logger = logger;
        _db = db;
        _configuration = configuration;
    }

    [HttpGet]
    public IActionResult Index()
    {
        UserModel userModel = new UserModel();
        return View(userModel);
    }

    [HttpPost]
    public IActionResult Index(UserModel userModel)
    {
        string sqlQuery = $"SELECT * FROM Users WHERE username='{userModel.username}' AND password='{userModel.password}'";

        var result = _db.Users.FromSqlRaw(sqlQuery).FirstOrDefault();

        if (result != null)
        {
            JWTHelper jwt = new JWTHelper(_configuration);

            string jwtToken = jwt.GenerateJwtToken(result.username, result.ID.ToString());

            Response.Cookies.Append("Token", jwtToken);
            Response.Redirect("/home/");

        }
        
        ViewData["Error"] = "Invalid Credentials!";
        return View();
    }

    [HttpGet]
    public IActionResult Create()
    {
        UserModel userModel = new UserModel();
        return View(userModel);
    }

    [HttpPost]
    public IActionResult Create(UserModel userModel)
    {

        if (string.IsNullOrEmpty(userModel.username) || string.IsNullOrEmpty(userModel.password))
        {
            ViewData["Message"] = "Username and Password cannot be empty!";
            return View();
        }

        string checkUserSqlQuery = $"SELECT * FROM Users WHERE username='{userModel.username}'";
        var result = _db.Users.FromSqlRaw(checkUserSqlQuery).FirstOrDefault();
        
        if (result == null)
        {
            string sqlQuery = $"INSERT INTO Users(username, password) VALUES('{userModel.username}','{userModel.password}')";
            _db.Database.ExecuteSqlRaw(sqlQuery);

            ViewData["Message"] = "User registered! Please login";
            return View();

        }

        ViewData["Message"] = "User Already Exists!";
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

