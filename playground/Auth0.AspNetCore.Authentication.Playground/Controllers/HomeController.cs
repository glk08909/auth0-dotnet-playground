using Auth0.AspNetCore.Authentication.Playground.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Auth0.AspNetCore.Authentication.Playground.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
         Debugger.Break();
        return View();
    }

    [Authorize(Roles = "Admin")]
    public IActionResult Admin()
    {
         Debugger.Break();
        return View();
    }

    public IActionResult Error()
    {
         Debugger.Break();
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}