using Identity.Domain.SharedKernel;
using System.Security.Claims;

namespace Identity.Domain.Extensions
{
    /// <summary>
    /// Provides extension methods for the <see cref="ClaimsPrincipal"/> class to retrieve user session details.
    /// This class is responsible for extracting user-specific information (such as user ID, email, roles, permissions, and tenant ID)
    /// from the claims associated with an authenticated user. The extensions are useful for managing authorization, user context, and tenant-specific data.
    /// </summary>
    public static class ClaimsPrincipalExtension
    {
        private const string Permission = nameof(Permission); // Constant for permission claim type
        private const string TenantIdClaim = "TenantId"; // Constant for tenant ID claim type

        /// <summary>
        /// Extracts user session information from the specified <see cref="ClaimsPrincipal"/>.
        /// This includes the user's email, unique identifier (UserId), roles, permissions, and tenant ID.
        /// Returns a default <see cref="UserSession"/> if the identity is unauthenticated or required claims are missing.
        /// </summary>
        /// <param name="claimsPrincipal">The <see cref="ClaimsPrincipal"/> representing the current authenticated user.</param>
        /// <returns>
        /// A populated <see cref="UserSession"/> object if valid claims exist; otherwise, a default <see cref="UserSession"/> instance.
        /// </returns>
        /// <remarks>
        /// This method ensures safe parsing of claims, including type conversion for user ID and tenant ID.
        /// It falls back to default values if any expected claim is absent or malformed.
        /// </remarks>
        public static UserSession GetUserSession(this ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null || !claimsPrincipal.Identity?.IsAuthenticated == true)
            {
                return new UserSession();
            }

            string? email = claimsPrincipal.FindFirstValue(ClaimTypes.Name);
            string? userIdStr = claimsPrincipal.FindFirstValue(ClaimTypes.Sid);
            string? tenantIdStr = claimsPrincipal.FindFirstValue(TenantIdClaim);

            if (!Guid.TryParse(userIdStr, out Guid userId) || string.IsNullOrWhiteSpace(email))
            {
                return new UserSession();
            }

            int tenantId = int.TryParse(tenantIdStr, out int parsedTenantId) ? parsedTenantId : 0;

            List<string> roles = claimsPrincipal.FindAll(ClaimTypes.Role).Select(r => r.Value).ToList();
            List<string> permissions = claimsPrincipal.FindAll(Permission).Select(p => p.Value).ToList();

            return new UserSession
            {
                Email = email,
                UserId = userId,
                Roles = roles,
                Permissions = permissions,
                TenantId = tenantId
            };
        }
    }
}