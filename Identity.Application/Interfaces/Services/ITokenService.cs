using Identity.Application.Dtos.Users;
using Identity.Domain.Entities;
using System.Security.Claims;

namespace Identity.Application.Interfaces.Services
{
    public interface ITokenService
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
        Task<TokenDto> CreateAsync(User user);

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
        Task<TokenDto> RefreshTokenAsync(TokenDto token);

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
        Task<bool> InvalidateUserTokensAsync(string email);

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
        Task<string> Get2FaTokenAsync(string email);

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
        Task<TokenDto> Verify2FaTokenAsync(string email, string token);

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
        Task<TokenDto> VerifyEmailTokenAsync(string email, string token);

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
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);

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
        Task<bool> DeleteAllUsedRefreshTokenAsync();

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
        Task<bool> RevokeAsync(string jti);
    }
}