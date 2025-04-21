using AutoMapper;
using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Repositories;
using Identity.Application.Interfaces.Services;
using Identity.Application.Services.Base;
using Identity.Domain.Constants;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Identity.Domain.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Identity.Application.Services
{
    public class TokenService(
        IRefreshTokenRepository refreshTokenRepository,
        UserManager<User> userManager,
        RoleManager<Role> roleManager,
        IPasswordHasher<User> passwordHasher,
        IOptions<ApplicationSettings> applicationSettings,
        IOptions<JwtSettings> jwtSettings,
        IMapper mapper,
        IHttpContextAccessor httpContextAccessor,
        IPermissionService permissionService) : UserAuthBaseService(userManager, roleManager, passwordHasher, applicationSettings, jwtSettings, mapper, httpContextAccessor), ITokenService
    {
        /// <summary>
        /// Creates a new access token (JWT) and associated refresh token for the specified user.
        /// </summary>
        /// <param name="user">
        /// The user for whom the token is being created.
        /// </param>
        /// <returns>
        /// A <see cref="Task{TokenDto}"/> representing the asynchronous operation,
        /// with a result containing the generated JWT and refresh token.
        /// </returns>
        /// <remarks>
        /// This method generates a JWT containing user claims and role-based permissions,
        /// signs it using configured credentials, and attaches any additional header values such as the tenant ID.
        /// A refresh token is also created and persisted for future access token renewal.
        /// </remarks>
        public async Task<TokenDto> CreateAsync(User user)
        {
            DateTime expireDate = DateTime.UtcNow.AddSeconds(TokenValidityInSeconds);

            IList<string>? roles = await _userManager.GetRolesAsync(user);

            IList<Permission> userPermissionClaims = _mapper.Map<IList<Permission>>(await permissionService.GetByRoleNamesAsync(roles));

            JwtSecurityToken token = CreateJwtToken(claims: CreateClaims(user, roles, userPermissionClaims), credentials: CreateSigningCredentials(), expiration: expireDate);

            Dictionary<string, object> additionalHeaders = new()
            {
                { "TenantId", TenantId }
            };

            AddHeadersToJwtHeader(token, additionalHeaders);

            RefreshToken refreshToken = CreateRefreshToken(token.Id, user.Id);

            _ = await refreshTokenRepository.CreateAsync(refreshToken);

            return new TokenDto
            {
                UserId = user.Id,
                Token = (new JwtSecurityTokenHandler()).WriteToken(token),
                RefreshToken = refreshToken.Token
            };
        }

        /// <summary>
        /// Generates a two-factor authentication (2FA) token for the user and sends it via email.
        /// </summary>
        /// <param name="email">The email of the user requesting the 2FA token.</param>
        /// <returns>The generated 2FA token as a string.</returns>
        /// <exception cref="NotFoundException">
        /// Thrown when the user with the specified email does not exist.
        /// </exception>
        /// <exception cref="UnhandledException">
        /// Thrown when token generation fails unexpectedly.
        /// </exception>
        /// <remarks>
        /// This method generates a time-based one-time password (OTP) using the default 2FA provider
        /// and sends it to the user's email address.
        /// </remarks>
        public async Task<string> Get2FaTokenAsync(string email)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException($"User with {email} is not found");

            string token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultProvider);

            if (string.IsNullOrEmpty(token))
            {
                throw new UnhandledException(ResponseMessage.UnknownError);
            }

            EmailHelper.SendEmailTwoFactorCode(user.Email!, token);

            return token;
        }

        /// <summary>
        /// Extracts the <see cref="ClaimsPrincipal"/> from an expired JWT access token without validating its lifetime.
        /// </summary>
        /// <param name="token">The expired JWT access token to extract claims from.</param>
        /// <returns>
        /// A <see cref="ClaimsPrincipal"/> containing the user's identity and claims if the token is valid and properly signed;
        /// otherwise, <c>null</c> if the token is malformed or its signature algorithm is invalid.
        /// </returns>
        /// <remarks>
        /// This method is typically used during the refresh token process, where access tokens may have expired,
        /// but the claims still need to be retrieved for issuing a new token. It disables lifetime validation
        /// but still ensures that the token is issued by a trusted issuer and has a valid signature.
        ///
        /// The method returns <c>null</c> if:
        /// - The token is null or malformed
        /// - The algorithm used to sign the token is not the expected one (e.g., not HMAC-SHA256)
        ///
        /// Signature validation, issuer, and audience checks are still enforced to prevent tampered or unauthorized tokens.
        /// </remarks>
        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
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

            JwtSecurityTokenHandler tokenHandler = new();
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken
                || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithmMethod, StringComparison.InvariantCultureIgnoreCase))
            {
                return null;
            }

            return principal;
        }

        /// <summary>
        /// Invalidates all refresh tokens associated with the specified user's email.
        /// </summary>
        /// <param name="email">The email of the user whose tokens should be invalidated.</param>
        /// <returns><c>true</c> if the operation completes successfully.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when no user exists with the specified email.
        /// </exception>
        /// <remarks>
        /// This method retrieves the user by email, then invalidates all their active refresh tokens and commits the changes.
        /// </remarks>
        public async Task<bool> InvalidateUserTokensAsync(string email)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new ArgumentException($"User with {email} doesn't exist.");

            await refreshTokenRepository.InvalidateUserTokens(user.Id);
            await refreshTokenRepository.CommitAsync();

            return true;
        }

        /// <summary>
        /// Refreshes an access token using a valid, non-expired, and unused refresh token.
        /// </summary>
        /// <param name="token">The expired access token and its corresponding refresh token.</param>
        /// <returns>
        /// A new <see cref="TokenDto"/> containing a refreshed access token and a new refresh token.
        /// </returns>
        /// <exception cref="InvalidCredentialException">
        /// Thrown when the provided access token or refresh token is invalid, expired, used, or does not match the stored token.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the access token has not yet expired.
        /// </exception>
        /// <exception cref="NotFoundException">
        /// Thrown when the user associated with the token cannot be found.
        /// </exception>
        /// <remarks>
        /// This method performs the following operations:
        /// <list type="bullet">
        /// <item>Extracts and validates claims from the expired access token.</item>
        /// <item>Ensures the token has actually expired before proceeding.</item>
        /// <item>Retrieves and validates the refresh token from the repository.</item>
        /// <item>Marks the refresh token as used and persists the change.</item>
        /// <item>Retrieves the user associated with the token from the claims.</item>
        /// <item>Generates and returns a new access and refresh token pair.</item>
        /// </list>
        /// </remarks>
        public async Task<TokenDto> RefreshTokenAsync(TokenDto token)
        {
            ClaimsPrincipal? principal = GetPrincipalFromExpiredToken(token.Token) ?? throw new InvalidCredentialException("Invalid token.");

            long tokenExpiryUnix = long.Parse(principal.Claims.Single(p => p.Type == JwtRegisteredClaimNames.Exp).Value);
            DateTime tokenExpiryDate = DateTime.UnixEpoch.AddSeconds(tokenExpiryUnix);

            if (tokenExpiryDate > DateTime.Now)
            {
                throw new InvalidOperationException("The access token has not expired yet.");
            }

            string jti = principal.Claims.Single(p => p.Type == JwtRegisteredClaimNames.Jti).Value;

            RefreshToken? storedRefreshToken = await refreshTokenRepository.FindByTokenAsync(token.RefreshToken);

            if (storedRefreshToken == null ||
                storedRefreshToken.JwtId != jti ||
                storedRefreshToken.ExpiryDate < DateTime.Now ||
                storedRefreshToken.Invalidated ||
                storedRefreshToken.Used)
            {
                throw new InvalidCredentialException("Invalid refresh token.");
            }

            storedRefreshToken.Used = true;

            refreshTokenRepository.Update(storedRefreshToken);
            await refreshTokenRepository.CommitAsync();

            string? email = principal.Claims.Single(p => p.Type == ClaimTypes.Email).Value;

            User? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException($"User with {email} not found!");

            TokenDto resource = await CreateAsync(user);

            return resource;
        }

        /// <summary>
        /// Verifies the provided two-factor authentication (2FA) token and generates a new access token upon success.
        /// </summary>
        /// <param name="email">The email of the user attempting to verify their 2FA token.</param>
        /// <param name="token">The 2FA token to verify.</param>
        /// <returns>
        /// A new <see cref="TokenDto"/> containing the authenticated user's access and refresh tokens.
        /// </returns>
        /// <exception cref="NotFoundException">
        /// Thrown when the user with the specified email cannot be found.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when the provided token is invalid or does not match.
        /// </exception>
        /// <remarks>
        /// This method checks if the provided OTP is valid using the default 2FA provider. Upon success, it issues new authentication tokens.
        /// </remarks>
        public async Task<TokenDto> Verify2FaTokenAsync(string email, string token)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException($"User with {email} not found!");

            bool verified = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultProvider, token);

            if (!verified)
            {
                throw new ArgumentException("OTP does not match, please try again.");
            }

            return await CreateAsync(user);
        }

        /// <summary>
        /// Verifies the provided email confirmation token and activates the user's email.
        /// </summary>
        /// <param name="email">The email address of the user to confirm.</param>
        /// <param name="token">The email confirmation token to verify.</param>
        /// <returns>
        /// A <see cref="TokenDto"/> containing newly issued access and refresh tokens for the verified user.
        /// </returns>
        /// <exception cref="NotFoundException">
        /// Thrown when the user with the specified email does not exist.
        /// </exception>
        /// <exception cref="InvalidCredentialException">
        /// Thrown when email confirmation fails.
        /// </exception>
        /// <remarks>
        /// This method attempts to confirm the user's email address using the provided token. If successful, it issues new authentication tokens.
        /// </remarks>
        public async Task<TokenDto> VerifyEmailTokenAsync(string email, string token)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException($"User with {email} not found!");

            IdentityResult? result = await _userManager.ConfirmEmailAsync(user, token);

            if (result == null || !result.Succeeded)
            {
                throw new InvalidCredentialException("Email verification failed, please try again.");
            }

            return await CreateAsync(user);
        }

        /// <summary>
        /// Deletes all refresh tokens that have been marked as used.
        /// </summary>
        /// <returns>
        /// A <see cref="Task{Boolean}"/> representing the asynchronous operation,
        /// with a result indicating whether the deletion was successful.
        /// </returns>
        /// <remarks>
        /// This operation is typically used as a cleanup task to remove refresh tokens
        /// that have already been consumed and are no longer valid.
        /// </remarks>
        public async Task<bool> DeleteAllUsedRefreshTokenAsync()
        {
            return await refreshTokenRepository.DeleteAllUsedToken();
        }

        /// <summary>
        /// Revokes a refresh token based on its unique JWT ID (jti).
        /// </summary>
        /// <param name="jti">
        /// The unique identifier (JWT ID) of the refresh token to be revoked.
        /// </param>
        /// <returns>
        /// A <see cref="Task{Boolean}"/> representing the asynchronous operation,
        /// with a result indicating whether the revocation was successful.
        /// </returns>
        /// <remarks>
        /// This operation marks the specified refresh token as revoked, preventing it
        /// from being used to obtain new access tokens. Typically used when a user logs
        /// out or when a security event requires invalidating a specific token.
        /// </remarks>
        public async Task<bool> RevokeAsync(string jti)
        {
            return await refreshTokenRepository.RevokeAsync(jti);
        }

        /// <summary>
        /// Adds custom headers to the JWT token's header if they are not already present.
        /// </summary>
        /// <param name="token">The JWT token to which headers should be added.</param>
        /// <param name="headersToAdd">A dictionary of headers to add to the JWT header.</param>
        /// <remarks>
        /// Existing headers in the token are preserved and will not be overwritten.
        /// </remarks>
        private static void AddHeadersToJwtHeader(JwtSecurityToken token, IDictionary<string, object> headersToAdd)
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

        /// <summary>
        /// Generates a secure, random refresh token using a 64-byte cryptographic random number generator.
        /// </summary>
        /// <returns>A base64-encoded string representing the refresh token.</returns>
        /// <remarks>
        /// This method is used to create a new refresh token when issuing a JWT.
        /// </remarks>
        private static string GenerateRefreshToken()
        {
            byte[]? randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        /// <summary>
        /// Constructs a list of claims for the JWT token, including user identity, roles, and optional additional claims.
        /// </summary>
        /// <param name="user">The user for whom the token is being created.</param>
        /// <param name="roles">A list of roles assigned to the user.</param>
        /// <param name="additionalPermissionClaims">Optional additional permission claims to include in the token.</param>
        /// <returns>An array of <see cref="Claim"/> objects to be embedded in the JWT token.</returns>
        /// <remarks>
        /// The method includes standard JWT claims such as subject, identifier, issue time, and custom claims like TenantId.
        /// </remarks>
        private Claim[] CreateClaims(User user, IList<string> roles, IList<Permission>? additionalPermissionClaims = null)
        {
            long iat = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds();

            List<Claim> claims = new List<Claim>()
            {
                new (JwtRegisteredClaimNames.Sub, _jwtSettings.Subject),
                new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new (JwtRegisteredClaimNames.Iat, iat.ToString(), ClaimValueTypes.Integer64),
                new (ClaimTypes.Sid, user.Id.ToString()),
                new (ClaimTypes.NameIdentifier, user.Id.ToString()),
                new (ClaimTypes.Name, user.UserName!),
                new (ClaimTypes.Email, user.Email!),
                new ("TenantId", TenantId.ToString())
            };

            foreach (string role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            if (additionalPermissionClaims != null && additionalPermissionClaims.Any())
            {
                foreach (Permission permissionClaim in additionalPermissionClaims)
                {
                    claims.Add(new Claim(nameof(Permission), permissionClaim.Name));
                }
            }

            return [.. claims];
        }

        /// <summary>
        /// Creates a new JWT token using the specified claims, signing credentials, and expiration time.
        /// </summary>
        /// <param name="claims">An array of <see cref="Claim"/> objects to include in the token payload.</param>
        /// <param name="credentials">The <see cref="SigningCredentials"/> used to sign the token.</param>
        /// <param name="expiration">The <see cref="DateTime"/> at which the token will expire.</param>
        /// <returns>
        /// A new instance of <see cref="JwtSecurityToken"/> that represents the generated JWT.
        /// </returns>
        /// <remarks>
        /// This method constructs the JWT with the configured issuer, audience, and claims, and signs it with the provided credentials.
        /// </remarks>
        private JwtSecurityToken CreateJwtToken(Claim[] claims, SigningCredentials credentials, DateTime expiration)
        {
            return new JwtSecurityToken(issuer: _jwtSettings.Issuer,
                                        audience: _jwtSettings.Audience,
                                        claims: claims,
                                        expires: expiration,
                                        signingCredentials: credentials);
        }

        /// <summary>
        /// Generates the signing credentials using the HMAC SHA-256 algorithm and the configured secret key.
        /// </summary>
        /// <returns>A <see cref="SigningCredentials"/> object used to sign the JWT token.</returns>
        /// <remarks>
        /// The signing key is derived from the configured <c>JwtSettings.Key</c> and includes the optional Key ID (Kid).
        /// </remarks>
        private SigningCredentials CreateSigningCredentials()
        {
            return new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)), SecurityAlgorithmMethod);
        }

        /// <summary>
        /// Creates a new <see cref="RefreshToken"/> instance for the specified user and JWT token ID.
        /// </summary>
        /// <param name="tokenId">The unique identifier (JTI) of the associated JWT access token.</param>
        /// <param name="userId">The ID of the user to whom the refresh token is issued.</param>
        /// <param name="minimumExpiryInDays">
        /// The minimum number of days the refresh token should remain valid.
        /// If the configured default expiry is greater, it will be used instead. Default is 1 day.
        /// </param>
        /// <returns>
        /// A new <see cref="RefreshToken"/> populated with a generated token, metadata, and calculated expiration date.
        /// </returns>
        /// <remarks>
        /// The method ensures that the refresh token's expiration period is never shorter than the specified minimum.
        /// It compares the configured default expiry (from settings) with the provided minimum and uses the larger value.
        /// </remarks>
        private RefreshToken CreateRefreshToken(string tokenId, Guid userId, double minimumExpiryInDays = 1)
        {
            double effectiveExpiryInDays = Math.Max(DefaultExpiryInDays, minimumExpiryInDays);

            return new RefreshToken
            {
                Token = GenerateRefreshToken(),
                JwtId = tokenId,
                UserId = userId,
                CreationDate = DateTime.Now,
                ExpiryDate = DateTime.Now.AddDays(effectiveExpiryInDays)
            };
        }
    }
}