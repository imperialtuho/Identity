using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// Controller responsible for token-related operations such as refreshing access tokens.
    /// </summary>
    /// <remarks>
    /// Uses API versioning with the route pattern <c>api/v{version}/[controller]</c>.
    /// </remarks>
    [ApiVersion(version: 1.0)]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class TokensController(ITokenService tokenService) : BaseController
    {
        /// <summary>
        /// Refreshes the access token using a valid refresh token.
        /// </summary>
        /// <param name="token">The expired access token and associated refresh token.</param>
        /// <returns>
        /// A 200 OK response containing a new <see cref="TokenDto"/> if the refresh operation succeeds.
        /// </returns>
        /// <response code="200">Returns a new access token and refresh token pair.</response>
        /// <response code="400">Returned if the request is malformed or the refresh token is invalid.</response>
        /// <response code="401">Returned if the token is expired, invalid, or does not match stored data.</response>
        /// <remarks>
        /// This endpoint allows clients to obtain a new JWT token without requiring the user to log in again,
        /// provided the refresh token is valid, not expired, and matches the original JWT ID.
        /// </remarks>
        [HttpPost("refresh")]
        [MapToApiVersion(version: 1.0)]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshTokenAsync([FromBody] TokenDto token)
        {
            return Result(await tokenService.RefreshTokenAsync(token), HttpStatusCode.OK);
        }

        /// <summary>
        /// Deletes all used (consumed or expired) refresh tokens from the system.
        /// </summary>
        /// <returns>
        /// An <see cref="IActionResult"/> containing the result of the deletion operation and an HTTP status code.
        /// </returns>
        /// <remarks>
        /// Only users with roles <c>SuperAdmin</c> or <c>Admin</c> and policies <c>Super</c>, <c>Read</c>, or <c>Write</c> are authorized to perform this action.
        /// This endpoint is versioned for API version 1.0.
        /// </remarks>
        [HttpDelete]
        [MapToApiVersion(version: 1.0)]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = $"{ApplicationPolicies.Special}")]
        public async Task<IActionResult> DeleteAllUsedTokenAsync()
        {
            return Result(await tokenService.DeleteAllUsedRefreshTokenAsync(), HttpStatusCode.OK);
        }

        /// <summary>
        /// Revokes a refresh token based on the provided JWT ID (jti).
        /// </summary>
        /// <param name="jti">The JWT ID of the refresh token to revoke.</param>
        /// <returns>
        /// An <see cref="IActionResult"/> indicating the result of the revocation operation,
        /// typically with an HTTP 200 OK status if successful.
        /// </returns>
        /// <remarks>
        /// This endpoint is secured and requires authorization. It is used to invalidate
        /// a refresh token by its unique identifier, preventing any further use of the token
        /// for generating access tokens.
        /// </remarks>
        [HttpDelete("revoke")]
        [MapToApiVersion(1.0)]
        [Authorize]
        public async Task<IActionResult> RevokeAsync([FromBody] string jti)
        {
            return Result(await tokenService.RevokeAsync(jti), HttpStatusCode.OK);
        }
    }
}