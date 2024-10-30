﻿using Identity.Domain.Entities;

namespace Identity.Application.Interfaces.Services
{
    public interface IRefreshTokenService
    {
        Task AddAsync(RefreshToken token);

        Task CommitAsync();

        Task<RefreshToken?> FindByTokenAsync(string token);

        Task InvalidateUserTokens(Guid userId);

        void Update(RefreshToken token);
    }
}