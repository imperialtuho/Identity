using Identity.Application.Configurations.Database;
using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Repositories;
using Identity.Domain.Entities;
using Identity.Infrastructure.Configurations.Repositories;
using Identity.Infrastructure.Database;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Identity.Infrastructure.Repositories.Providers.Identity
{
    public class JwtTokenRepository : DbSqlConnectionEFRepositoryBase<ApplicationDbContext, RefreshToken>, ITokenRepository
    {
        private const string SecurityAlgorithmMethod = SecurityAlgorithms.HmacSha256Signature;
        private readonly JwtSettings _jwtSettings;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public JwtTokenRepository(IOptions<JwtSettings> options,
            ISqlConnectionFactory sqlConnectionFactory,
            IHttpContextAccessor httpContextAccessor,
            IRefreshTokenRepository refreshTokenRepository) : base(sqlConnectionFactory, httpContextAccessor)
        {
            _jwtSettings = options.Value;
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task<TokenDto> CreateTokenAsync(User user, IList<string> roles, IList<Claim>? additionalClaims = null, int? tenantId = null)
        {
            var expiration = DateTime.UtcNow.AddSeconds(double.Parse(_jwtSettings.TokenValidityInSeconds));

            JwtSecurityToken token = CreateJwtToken(CreateClaims(user, roles, additionalClaims), CreateSigningCredentials(), expiration);

            var tokenHandler = new JwtSecurityTokenHandler();

            var additionalHeaders = new Dictionary<string, object>()
            {
                { "TenantId", tenantId ?? DefaultTenantId }
            };

            AddHeadersToJwtHeader(token, additionalHeaders);

            var refreshToken = new RefreshToken
            {
                Token = GenerateRefreshToken(),
                JwtId = token.Id,
                UserId = user.Id,
                CreationDate = DateTime.Now,
                ExpiryDate = DateTime.Now.AddDays(double.Parse(_jwtSettings.RefreshTokenValidityInDays))
            };

            await _refreshTokenRepository.AddAsync(refreshToken);
            await _refreshTokenRepository.CommitAsync();

            return new TokenDto
            {
                UserId = user.Id,
                Token = tokenHandler.WriteToken(token),
                RefreshToken = refreshToken.Token
            };
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, // We don't validate this due to expired token needs to be refreshed. So, we'll check in RefreshToken's ExpiryDate.
                RequireExpirationTime = true,
                ValidateIssuerSigningKey = true,
                ValidAudience = _jwtSettings.Audience,
                ValidIssuer = _jwtSettings.Issuer,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)) { KeyId = _jwtSettings.Kid }
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken
                || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithmMethod, StringComparison.InvariantCultureIgnoreCase))
            {
                return null;
            }

            return principal;
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private void AddHeadersToJwtHeader(JwtSecurityToken token, IDictionary<string, object> headersToAdd)
        {
            foreach (KeyValuePair<string, object> header in headersToAdd)
            {
                // Avoid overwriting existing headers with the same key
                if (!token.Header.ContainsKey(header.Key))
                {
                    token.Header.Add(header.Key, header.Value);
                }
            }
        }

        private Claim[] CreateClaims(User user, IList<string> roles, IList<Claim>? additionalClaims = null)
        {
            long iat = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds();

            var claims = new List<Claim>()
            {
                new (JwtRegisteredClaimNames.Sub, _jwtSettings.Subject),
                new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new (JwtRegisteredClaimNames.Iat, iat.ToString(), ClaimValueTypes.Integer64),
                new (ClaimTypes.Sid, user.Id.ToString()),
                new (ClaimTypes.NameIdentifier, user.Id.ToString()),
                new (ClaimTypes.Name, user.UserName!),
                new (ClaimTypes.Email, user.Email!),
                new ("TenantId", user.TenantId?.ToString() ?? DefaultTenantId.ToString())
            };

            foreach (string role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            if (additionalClaims != null && additionalClaims.Any())
            {
                foreach (Claim claim in additionalClaims)
                {
                    claims.Add(claim);
                }
            }

            return [.. claims];
        }

        private JwtSecurityToken CreateJwtToken(Claim[] claims, SigningCredentials credentials, DateTime expiration)
        {
            return new JwtSecurityToken(issuer: _jwtSettings.Issuer,
                                        audience: _jwtSettings.Audience,
                                        claims: claims,
                                        expires: expiration,
                                        signingCredentials: credentials);
        }

        private SigningCredentials CreateSigningCredentials()
        {
            return new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)) { KeyId = _jwtSettings.Kid }, SecurityAlgorithmMethod);
        }
    }
}