using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuthTest.Models;
using OAuthTest.Services;

namespace OAuthTest.Controllers;

[ApiController]
[Route("auth")]
[Produces(MediaTypeNames.Application.Json)]
public sealed class AuthController : ControllerBase
{
    private const string DemoUserId = "user-1";
    private const string DemoUsername = "demo";
    private const string DemoPassword = "P@ssw0rd!";

    private readonly ITokenService _tokenService;
    private readonly IRefreshTokenStore _refreshTokenStore;

    public AuthController(ITokenService tokenService, IRefreshTokenStore refreshTokenStore)
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

        var tokens = _tokenService.CreateTokens(DemoUserId, DemoUsername);
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

        if (userId != DemoUserId)
        {
            return Unauthorized();
        }

        var tokens = _tokenService.CreateTokens(DemoUserId, DemoUsername);
        return Ok(tokens);
    }

    [HttpPost("logout")]
    [Authorize]
    public IActionResult Logout()
    {
        _refreshTokenStore.RevokeAllForUser(DemoUserId);
        return NoContent();
    }

    private static bool IsValidUser(string username, string password) =>
        username == DemoUsername && password == DemoPassword;
}
