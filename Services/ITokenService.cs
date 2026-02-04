using System.Security.Claims;
using OAuthTest.Models;

namespace OAuthTest.Services;

public interface ITokenService
{
    TokenResponse CreateTokens(string userId, string username, IEnumerable<Claim>? additionalClaims = null);
}
