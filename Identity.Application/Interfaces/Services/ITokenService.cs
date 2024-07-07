using Identity.Application.Dtos.Users;
using System.Security.Claims;

namespace Identity.Application.Interfaces.Services
{
    public interface ITokenService
    {
        Task<TokenDto> CreateTokenAsync(UserDto user, IList<string> roles, IList<Claim>? additionalClaims = null);

        ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);
    }
}