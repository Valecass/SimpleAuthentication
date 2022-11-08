using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace SimpleAuthentication.JwtBearer;

internal class JwtBearerService : IJwtBearerService
{
    private readonly JwtBearerSettings jwtBearerSettings;
    private readonly IOptions<SimpleAuthenticationOptions> simpleAuthenticationOptions;

    public JwtBearerService(IOptions<JwtBearerSettings> jwtBearerSettingsOptions, IOptions<SimpleAuthenticationOptions> simpleAuthenticationOptions)
    {
        jwtBearerSettings = jwtBearerSettingsOptions.Value;
        this.simpleAuthenticationOptions = simpleAuthenticationOptions;
    }

    public string CreateToken(string userName, IList<Claim>? claims = null, string? issuer = null, string? audience = null, DateTime? absoluteExpiration = null)
    {
        claims ??= new List<Claim>();
        claims.Update(ClaimTypes.Name, userName);
        claims.Remove(JwtRegisteredClaimNames.Aud);

        var now = DateTime.UtcNow;

        var jwtSecurityToken = new JwtSecurityToken(
            issuer ?? jwtBearerSettings.Issuers?.FirstOrDefault(),
            audience ?? jwtBearerSettings.Audiences?.FirstOrDefault(),
            claims,
            now,
            absoluteExpiration ?? (jwtBearerSettings.ExpirationTime.GetValueOrDefault() > TimeSpan.Zero ? now.Add(jwtBearerSettings.ExpirationTime!.Value) : DateTime.MaxValue),
            new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtBearerSettings.SecurityKey)), jwtBearerSettings.Algorithm));

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.WriteToken(jwtSecurityToken);

        return token;
    }

    public async Task<(string token, string refreshToken)> CreateTokenAndRefreshTokenAsync(string userName, IList<Claim>? claims = null, string? issuer = null, string? audience = null, DateTime? absoluteExpiration = null)
    {
        if (!jwtBearerSettings.EnableRefreshToken)
        {
            throw new NotSupportedException("Refresh token not enabled");
        }

        var jwtToken = CreateToken(userName, claims, issuer, audience, absoluteExpiration);
        var createTokenMethod = simpleAuthenticationOptions.Value.CreateAndGetRefreshTokenMethod;
        if (createTokenMethod == null)
        {
            throw new NotSupportedException("Create token method not found");
        }

        var refreshToken = await createTokenMethod.Invoke(userName);
        return (jwtToken, refreshToken);
    }

    public ClaimsPrincipal ValidateToken(string token, bool validateLifetime)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = jwtBearerSettings.Issuers?.Any() ?? false,
            ValidIssuers = jwtBearerSettings.Issuers,
            ValidateAudience = jwtBearerSettings.Audiences?.Any() ?? false,
            ValidAudiences = jwtBearerSettings.Audiences,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtBearerSettings.SecurityKey)),
            RequireExpirationTime = true,
            ValidateLifetime = validateLifetime,
            ClockSkew = jwtBearerSettings.ClockSkew
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken || jwtSecurityToken.Header.Alg != jwtBearerSettings.Algorithm)
        {
            throw new SecurityTokenException("Token is not a JWT or uses an unexpected algorithm.");
        }

        return principal;
    }

    public string RefreshToken(string token, bool validateLifetime, DateTime? absoluteExpiration = null)
    {
        var principal = ValidateToken(token, validateLifetime);
        var claims = (principal.Identity as ClaimsIdentity)!.Claims.ToList();

        var userName = claims.First(c => c.Type == ClaimTypes.Name).Value;
        var issuer = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iss)?.Value;
        var audience = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Aud)?.Value;

        var newToken = CreateToken(userName, claims, issuer, audience, absoluteExpiration);
        return newToken;
    }

    public async Task<(string token, string refreshToken)> RefreshTokenAsync(string token, string refreshToken, DateTime? absoluteExpiration = null)
    {
        var principal = ValidateToken(token, false);
        var claims = (principal.Identity as ClaimsIdentity)!.Claims.ToList();
        var userName = claims.First(c => c.Type == ClaimTypes.Name).Value;

        var validateTokenMethod = simpleAuthenticationOptions.Value.VerifyRefreshTokenMethod;
        if (validateTokenMethod == null)
        {
            throw new NotSupportedException("Refresh token verification method not found");
        }

        var isRefreshTokenValid = await validateTokenMethod.Invoke(refreshToken, userName);
        if (!isRefreshTokenValid)
        {
            throw new ArgumentException("Refresh token is not valid");
        }

        var issuer = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iss)?.Value;
        var audience = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Aud)?.Value;

        var newTokens = await CreateTokenAndRefreshTokenAsync(userName, claims, issuer, audience, absoluteExpiration);

        return newTokens;
    }    
}
