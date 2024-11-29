using Identity.Application.Configurations.Database;
using Identity.Application.Interfaces.Repositories;
using Identity.Domain.Entities;
using Identity.Infrastructure.Configurations.Repositories;
using Identity.Infrastructure.Database;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

namespace Identity.Infrastructure.Repositories.Providers.Identity
{
    public class PermissionRepository : DbSqlConnectionEFRepositoryBase<ApplicationDbContext, Permission>, IPermissionRepository
    {
        public PermissionRepository(ISqlConnectionFactory sqlConnectionFactory, IHttpContextAccessor httpContextAccessor) : base(sqlConnectionFactory, httpContextAccessor)
        {
        }

        public async Task<IList<Permission>> GetByRoleIdAsync(Guid roleId)
        {
            return await _dbContext.RolePermissions.Where(rolePermission => rolePermission.RoleId == roleId).Select(p => p.Permission).ToListAsync();
        }
    }
}