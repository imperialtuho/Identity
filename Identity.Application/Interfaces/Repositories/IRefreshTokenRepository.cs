using Identity.Domain.Entities;

namespace Identity.Application.Interfaces.Repositories
{
    public interface IRefreshTokenRepository : IEntityFrameworkGenericRepository<RefreshToken>
    {
        Task<RefreshToken?> FindByTokenAsync(string token);

        Task InvalidateUserTokens(Guid userId);

        void Update(RefreshToken token);
    }
}