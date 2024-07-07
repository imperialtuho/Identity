using Identity.Application.Configurations.Settings;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;

namespace Identity.Api.Middlewares.Authentication
{
    public class AuthenticationMiddlewareHandler : AuthenticationHandler<AuthenticationMiddlewareOptions>
    {
        /// <summary>
        /// The logger.
        /// </summary>
        private readonly ILogger _logger;

        /// <summary>
        /// The IdentityUrl.
        /// </summary>
        public static string? IdentityUrl { get; set; }

        /// <summary>
        /// The Memorycache.
        /// </summary>
        private readonly IMemoryCache _cache;

        /// <summary>
        /// The cacheKey.
        /// </summary>
        private const string CacheKey = "JwtSettings";

        /// <summary>
        /// The Unauthorized string constant.
        /// </summary>
        private const string Unauthorized = "Unauthorized";

        /// <summary>
        /// The Bearer.
        /// </summary>
        private const string Bearer = "Bearer";

        /// <summary>
        /// The IHttpClientFactory.
        /// </summary>
        private readonly IHttpClientFactory _httpClientFactory;

        /// <summary>
        /// The AuthenticationMiddlewareHandler constructor.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="logger">The logger.</param>
        /// <param name="encoder">The encoder.</param>
        /// <param name="cache">The cache.</param>
        /// <param name="httpClientFactory">The httpClientFactory.</param>
        public AuthenticationMiddlewareHandler(
            IOptionsMonitor<AuthenticationMiddlewareOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            IMemoryCache cache,
            IHttpClientFactory httpClientFactory) : base(options, logger, encoder)
        {
            _cache = cache;
            _logger = logger.CreateLogger<AuthenticationMiddlewareHandler>();
            _httpClientFactory = httpClientFactory;
        }

        /// <summary>
        /// Handle Authenticate Async.
        /// </summary>
        /// <returns>Task{AuthenticateResult}</returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("Authorization", out Microsoft.Extensions.Primitives.StringValues value))
            {
                return AuthenticateResult.Fail(Unauthorized);
            }

            string? authorizationHeader = value;

            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            if (!authorizationHeader.StartsWith(Bearer, StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.Fail(Unauthorized);
            }

            string? token = authorizationHeader.Substring(Bearer.Length).Trim();

            if (string.IsNullOrEmpty(token))
            {
                return AuthenticateResult.Fail(Unauthorized);
            }

            try
            {
                return await ValidateTokenAsync(token);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ValidateToken Failed");
                return AuthenticateResult.Fail(ex.Message);
            }
        }

        private async Task<AuthenticateResult> ValidateTokenAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return AuthenticateResult.Fail(Unauthorized);
            }

            ClaimsIdentity identity = await GetIdentityFromTokenAsync(token);
            identity.AddClaim(new Claim("AccessToken", token));

            GenericPrincipal principal = new GenericPrincipal(identity, null);
            AuthenticationTicket ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }

        private async Task<ClaimsIdentity> GetIdentityFromTokenAsync(string token, bool isRetry = false)
        {
            try
            {
                var tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ValidateIssuerSigningKey = true,
                };

                JwtSettings jwtSettings = await GetJwtSettingsAsync() ?? throw new NotFoundException($"{nameof(JwtSettings)} is not found or not setup!");

                tokenValidationParameters.ValidateTokenReplay = true;
                tokenValidationParameters.ValidAudience = jwtSettings.Audience;
                tokenValidationParameters.ValidIssuer = jwtSettings.Issuer;
                tokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key));

                var tokenDecoder = new JwtSecurityTokenHandler();

                ClaimsPrincipal principal = tokenDecoder.ValidateToken(token, tokenValidationParameters, out _);

                return principal.Identities.First();
            }
            catch (SecurityTokenExpiredException ex)
            {
                string errorMessage = "Call to {0} failed with {1}";
                _logger.LogError(ex, errorMessage, nameof(GetIdentityFromTokenAsync), nameof(SecurityTokenExpiredException));

                if (!isRetry)
                {
                    RemoveJwtSettingsCache();
                    return await GetIdentityFromTokenAsync(token, true);
                }

                throw new SecurityTokenExpiredException();
            }
            catch (Exception ex)
            {
                string errorMessage = "Call to {0} failed with message: {1}";
                _logger.LogError(ex, errorMessage, nameof(GetIdentityFromTokenAsync), ex.Message);

                throw new UnhandledException();
            }
        }

        /// <summary>
        /// Handle Get JwtSettings From Memorycache.
        /// </summary>
        /// <returns>JwtSettings.</returns>
        public async Task<JwtSettings?> GetJwtSettingsAsync()
        {
            try
            {
                if (_cache.TryGetValue(CacheKey, out JwtSettings? cacheSettings))
                {
                    return cacheSettings;
                }

                using HttpClient client = _httpClientFactory.CreateClient();
                HttpResponseMessage response = await client.GetAsync($"{IdentityUrl}auth/settings");

                if (response.IsSuccessStatusCode)
                {
                    string? settingsJson = await response.Content.ReadAsStringAsync();
                    JwtSettings? settings = JsonConvert.DeserializeObject<JwtSettings>(settingsJson);

                    if (settings != null)
                    {
                        _cache.Set(CacheKey, settings, TimeSpan.FromDays(1));

                        return settings;
                    }
                }

                return default;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);

                return default;
            }
        }

        /// <summary>
        /// Handle Remove JwtSettings In Memorycache.
        /// </summary>
        /// <returns>Void</returns>
        public void RemoveJwtSettingsCache()
        {
            _cache.Remove(CacheKey);
        }
    }
}