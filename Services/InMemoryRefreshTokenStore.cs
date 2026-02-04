using System.Collections.Concurrent;

namespace OAuthTest.Services;

public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, (string UserId, DateTimeOffset ExpiresAtUtc)> _tokens = new();
    private readonly ConcurrentDictionary<string, ConcurrentBag<string>> _userTokens = new();

    public bool TryStore(string userId, string refreshTokenHash, DateTimeOffset expiresAtUtc)
    {
        var stored = _tokens.TryAdd(refreshTokenHash, (userId, expiresAtUtc));
        if (stored)
        {
            var bag = _userTokens.GetOrAdd(userId, _ => new ConcurrentBag<string>());
            bag.Add(refreshTokenHash);
        }

        return stored;
    }

    public bool TryConsume(string refreshTokenHash, out string userId, out DateTimeOffset expiresAtUtc)
    {
        if (_tokens.TryRemove(refreshTokenHash, out var entry))
        {
            userId = entry.UserId;
            expiresAtUtc = entry.ExpiresAtUtc;
            return true;
        }

        userId = "";
        expiresAtUtc = default;
        return false;
    }

    public void RevokeAllForUser(string userId)
    {
        if (!_userTokens.TryRemove(userId, out var bag))
        {
            return;
        }

        while (bag.TryTake(out var token))
        {
            _tokens.TryRemove(token, out _);
        }
    }
}
