using Identity.Application.Configurations.Database;
using Identity.Application.Interfaces.Repositories;
using Identity.Domain.Entities;
using Identity.Infrastructure.Configurations;
using Identity.Infrastructure.Database;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

namespace Identity.Infrastructure.Repositories.Providers.Identity
{
    public class RefreshTokenRepository : DbSqlConnectionEFRepositoryBase<ApplicationDbContext, RefreshToken>, IRefreshTokenRepository
    {
        public RefreshTokenRepository(ISqlConnectionFactory sqlConnectionFactory, IHttpContextAccessor httpContextAccessor) : base(sqlConnectionFactory, httpContextAccessor)
        {
        }

        public async Task<RefreshToken?> FindByTokenAsync(string token)
        {
            return await _dbContext.RefreshTokens.FirstOrDefaultAsync(t => t.Token == token);
        }

        public async Task InvalidateUserTokens(Guid userId)
        {
            IList<RefreshToken> tokens = await _dbContext.RefreshTokens.Where(rt => rt.UserId == userId).ToListAsync();

            foreach (RefreshToken token in tokens)
            {
                token.Invalidated = true;
                _dbContext.RefreshTokens.Update(token);
            }
        }

        public void Update(RefreshToken token)
        {
            _dbContext.RefreshTokens.Update(token);
        }
    }
}