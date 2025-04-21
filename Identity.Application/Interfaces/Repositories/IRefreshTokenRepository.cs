using Identity.Domain.Entities;

namespace Identity.Application.Interfaces.Repositories
{
    public interface IRefreshTokenRepository : IEntityFrameworkGenericRepository<RefreshToken>
    {
        /// <summary>
        /// Finds a refresh token by its token string.
        /// </summary>
        /// <param name="token">The refresh token string to search for.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the asynchronous operation.
        /// The task result contains the <see cref="RefreshToken"/> if found; otherwise, <c>null</c>.
        /// </returns>
        Task<RefreshToken?> FindByTokenAsync(string token);

        /// <summary>
        /// Invalidates all refresh tokens associated with a specific user.
        /// </summary>
        /// <param name="userId">The unique identifier of the user whose tokens should be invalidated.</param>
        /// <returns>A <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task InvalidateUserTokens(Guid userId);

        /// <summary>
        /// Creates and persists a new refresh token.
        /// </summary>
        /// <param name="refreshToken">The <see cref="RefreshToken"/> to create.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the asynchronous operation.
        /// The task result contains the created <see cref="RefreshToken"/>.
        /// </returns>
        Task<RefreshToken> CreateAsync(RefreshToken refreshToken);

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
        Task<bool> DeleteAllUsedToken();

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