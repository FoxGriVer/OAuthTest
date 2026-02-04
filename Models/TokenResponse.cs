namespace OAuthTest.Models;

public sealed class TokenResponse
{
    public string AccessToken { get; init; } = "";
    public DateTimeOffset AccessTokenExpiresAtUtc { get; init; }
    public string RefreshToken { get; init; } = "";
    public DateTimeOffset RefreshTokenExpiresAtUtc { get; init; }
}
