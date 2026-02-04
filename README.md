# OAuthTest

Simple ASP.NET Core project demonstrating JWT auth with access and refresh tokens.

## Run

```bash
dotnet run
```

## Endpoints

- `POST /auth/login`
  - body: `{ "username": "demo", "password": "P@ssw0rd!" }`
- `POST /auth/refresh`
  - body: `{ "refreshToken": "<token>" }`
- `POST /auth/logout` (requires Authorization header with Bearer token)

## Notes

- Update `Jwt:SigningKey` in `appsettings.json` before production use.
- Refresh tokens are stored in memory for demo purposes.
