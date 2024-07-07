using Identity.Domain.Entities;

namespace Identity.Application.Interfaces.Repositories
{
    public interface IRefreshTokenRepository
    {
        Task AddAsync(RefreshToken token);

        Task<RefreshToken?> FindByTokenAsync(string token);

        Task InvalidateUserTokens(string userId);

        void Update(RefreshToken token);

        Task CompleteAsync();
    }
}