﻿using Identity.Application.Dtos.Users;
using Identity.Domain.Entities;
using System.Security.Claims;

namespace Identity.Application.Interfaces.Repositories
{
    public interface ITokenRepository
    {
        Task<TokenDto> CreateTokenAsync(User user, IList<string> roles, IList<Claim>? additionalClaims = null, int tenantId = 0);

        ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);
    }
}