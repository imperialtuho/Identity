using Identity.Domain.SharedKernel;
using System.Security.Claims;

namespace Identity.Domain.Extensions
{
    public static class ClaimsPrincipalExtension
    {
        public static UserSession GetUserSession(this ClaimsPrincipal claimsPrincipal)
        {
            string? userEmail = claimsPrincipal?.FindFirst(ClaimTypes.Email)?.Value;
            string? userStringId = claimsPrincipal?.FindFirst(ClaimTypes.Sid)?.Value;
            string? tenantId = claimsPrincipal?.FindFirst("tenantId")?.Value ?? "0";
            var userSession = new UserSession();

            if (string.IsNullOrWhiteSpace(userStringId))
            {
                return userSession;
            }

            List<string>? roles = claimsPrincipal!.Claims.Where(c => c.Type.Equals(ClaimTypes.Role)).Select(c => c.Value).ToList();

            var result = Guid.TryParse(userStringId, out Guid userId);

            return !result ? userSession : new UserSession()
            {
                Email = userEmail,
                UserId = userId,
                Roles = roles,
                TenantId = int.Parse(tenantId)
            };
        }
    }
}