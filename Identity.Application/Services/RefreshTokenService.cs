using Identity.Application.Interfaces.Repositories;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Entities;

namespace Identity.Application.Services
{
    public class RefreshTokenService : IRefreshTokenService
    {
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public RefreshTokenService(IRefreshTokenRepository refreshTokenRepository)
        {
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task AddAsync(RefreshToken token)
        {
            await _refreshTokenRepository.AddAsync(token);
        }

        public async Task CompleteAsync()
        {
            await _refreshTokenRepository.CommitAsync();
        }

        public async Task<RefreshToken?> FindByTokenAsync(string token)
        {
            return await _refreshTokenRepository.FindByTokenAsync(token);
        }

        public async Task InvalidateUserTokens(Guid userId)
        {
            await _refreshTokenRepository.InvalidateUserTokens(userId);
        }

        public void Update(RefreshToken token)
        {
            _refreshTokenRepository.Update(token);
        }
    }
}