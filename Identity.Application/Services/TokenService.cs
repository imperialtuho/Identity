using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Repositories;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Entities;
using Mapster;
using System.Security.Claims;

namespace Identity.Application.Services
{
    public class TokenService : ITokenService
    {
        private readonly ITokenRepository _tokenRepository;

        public TokenService(ITokenRepository tokenRepository)
        {
            _tokenRepository = tokenRepository;
        }

        public async Task<TokenDto> CreateAsync(UserDto user, IList<string> roles, IList<Claim>? additionalClaims = null)
        {
            return await _tokenRepository.CreateTokenAsync(user.Adapt<User>(), roles, additionalClaims);
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            return _tokenRepository.GetPrincipalFromExpiredToken(token);
        }
    }
}