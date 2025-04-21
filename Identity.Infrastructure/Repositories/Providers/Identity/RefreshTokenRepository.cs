using Identity.Application.Configurations.Database;
using Identity.Application.Interfaces.Repositories;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Identity.Infrastructure.Configurations.Repositories;
using Identity.Infrastructure.Database;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Identity.Infrastructure.Repositories.Providers.Identity
{
    public class RefreshTokenRepository : DbSqlConnectionEFRepositoryBase<ApplicationDbContext, RefreshToken>, IRefreshTokenRepository
    {
        public RefreshTokenRepository(ISqlConnectionFactory sqlConnectionFactory,
            IHttpContextAccessor httpContextAccessor,
            ILogger<RefreshTokenRepository> logger) : base(sqlConnectionFactory, httpContextAccessor, logger)
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

        public async Task<RefreshToken> CreateAsync(RefreshToken refreshToken)
        {
            return await AddWithSaveChangesAndReturnModelAsync(refreshToken);
        }

        public async Task<bool> DeleteAllUsedToken()
        {
            return await ForceDeleteWhereAsync(t => t.Used);
        }

        public async Task<bool> RevokeAsync(string jti)
        {
            RefreshToken? refreshToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(t => t.JwtId == jti)
                                        ?? throw new NotFoundException($"Refresh token with jti {jti} not found!.");

            if (refreshToken != null)
            {
                refreshToken.Invalidated = true;

                return await UpdateAndSaveChangesAsync(refreshToken);
            }

            return false;
        }
    }
}