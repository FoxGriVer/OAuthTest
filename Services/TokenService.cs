using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OAuthTest.Models;

namespace OAuthTest.Services;

public sealed class TokenService : ITokenService
{
    private readonly IRefreshTokenStore _refreshTokenStore;
    private readonly IConfiguration _configuration;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();

    public TokenService(IRefreshTokenStore refreshTokenStore, IConfiguration configuration)
    {
        _refreshTokenStore = refreshTokenStore;
        _configuration = configuration;
    }

    public TokenResponse CreateTokens(string userId, string username, IEnumerable<Claim>? additionalClaims = null)
    {
        var jwtSettings = _configuration.GetSection("Jwt");
        var issuer = jwtSettings["Issuer"];
        var audience = jwtSettings["Audience"];
        var signingKey = jwtSettings["SigningKey"];
        var accessTokenMinutes = int.Parse(jwtSettings["AccessTokenMinutes"]!);
        var refreshTokenDays = int.Parse(jwtSettings["RefreshTokenDays"]!);

        var now = DateTimeOffset.UtcNow;
        var accessTokenExpiresAtUtc = now.AddMinutes(accessTokenMinutes);
        var refreshTokenExpiresAtUtc = now.AddDays(refreshTokenDays);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.UniqueName, username),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        };

        if (additionalClaims is not null)
        {
            claims.AddRange(additionalClaims);
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: accessTokenExpiresAtUtc.UtcDateTime,
            signingCredentials: credentials);

        var accessToken = _tokenHandler.WriteToken(token);
        var refreshToken = CreateSecureRefreshToken();
        var refreshTokenHash = HashRefreshToken(refreshToken);

        _refreshTokenStore.TryStore(userId, refreshTokenHash, refreshTokenExpiresAtUtc);

        return new TokenResponse
        {
            AccessToken = accessToken,
            AccessTokenExpiresAtUtc = accessTokenExpiresAtUtc,
            RefreshToken = refreshToken,
            RefreshTokenExpiresAtUtc = refreshTokenExpiresAtUtc
        };
    }

    public static string HashRefreshToken(string refreshToken)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(refreshToken);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hash);
    }

    private static string CreateSecureRefreshToken()
    {
        Span<byte> data = stackalloc byte[32];
        RandomNumberGenerator.Fill(data);
        return Convert.ToBase64String(data);
    }
}
