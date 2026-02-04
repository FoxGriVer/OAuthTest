using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using OAuthTest.Models;
using OAuthTest.Services;

namespace OAuthTest.Controllers;

[ApiController]
[Route("auth")]
[Produces(MediaTypeNames.Application.Json)]
public sealed class AuthController : ControllerBase
{
    private readonly ITokenService _tokenService;
    private readonly IRefreshTokenStore _refreshTokenStore;
    private static readonly Lazy<DemoUserConfig> DemoUser = new(LoadDemoUser);

    public AuthController(
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore)
    {
        _tokenService = tokenService;
        _refreshTokenStore = refreshTokenStore;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public ActionResult<TokenResponse> Login([FromBody] LoginRequest request)
    {
        if (!IsValidUser(request.Username, request.Password))
        {
            return Unauthorized();
        }

        var tokens = _tokenService.CreateTokens(DemoUser.Value.UserId, DemoUser.Value.Username);
        return Ok(tokens);
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public ActionResult<TokenResponse> Refresh([FromBody] RefreshRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return BadRequest();
        }

        var refreshTokenHash = TokenService.HashRefreshToken(request.RefreshToken);
        if (!_refreshTokenStore.TryConsume(refreshTokenHash, out var userId, out var expiresAtUtc))
        {
            return Unauthorized();
        }

        if (expiresAtUtc <= DateTimeOffset.UtcNow)
        {
            return Unauthorized();
        }

        if (userId != DemoUser.Value.UserId)
        {
            return Unauthorized();
        }

        var tokens = _tokenService.CreateTokens(DemoUser.Value.UserId, DemoUser.Value.Username);
        return Ok(tokens);
    }

    [HttpPost("logout")]
    [Authorize]
    public IActionResult Logout()
    {
        _refreshTokenStore.RevokeAllForUser(DemoUser.Value.UserId);
        return NoContent();
    }

    private bool IsValidUser(string username, string password) =>
        username == DemoUser.Value.Username && password == DemoUser.Value.Password;

    private static DemoUserConfig LoadDemoUser()
    {
        var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        var builder = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .AddJsonFile($"appsettings.{environment}.json", optional: true, reloadOnChange: false)
            .AddEnvironmentVariables();

        var config = builder.Build();
        var section = config.GetSection("DemoUser");

        return new DemoUserConfig
        {
            UserId = section["UserId"] ?? "",
            Username = section["Username"] ?? "",
            Password = section["Password"] ?? ""
        };
    }

    private sealed class DemoUserConfig
    {
        public string UserId { get; init; } = "";
        public string Username { get; init; } = "";
        public string Password { get; init; } = "";
    }
}
