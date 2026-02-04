namespace OAuthTest.Services;

public interface IRefreshTokenStore
{
    bool TryStore(string userId, string refreshTokenHash, DateTimeOffset expiresAtUtc);
    bool TryConsume(string refreshTokenHash, out string userId, out DateTimeOffset expiresAtUtc);
    void RevokeAllForUser(string userId);
}
