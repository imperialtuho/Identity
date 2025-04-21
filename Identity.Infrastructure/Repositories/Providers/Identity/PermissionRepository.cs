using Identity.Application.Configurations.Database;
using Identity.Application.Interfaces.Repositories;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Identity.Infrastructure.Configurations.Repositories;
using Identity.Infrastructure.Database;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Data;

namespace Identity.Infrastructure.Repositories.Providers.Identity
{
    public class PermissionRepository(ISqlConnectionFactory sqlConnectionFactory,
        IHttpContextAccessor httpContextAccessor,
        ILogger<PermissionRepository> logger) : DbSqlConnectionEFRepositoryBase<ApplicationDbContext, Permission>(sqlConnectionFactory, httpContextAccessor, logger), IPermissionRepository
    {
        public async Task<bool> AssignToRoleAsync(Guid roleId, IList<Guid> permissionIds)
        {
            // Get existing RolePermission entries for this role and these permissionIds
            List<RolePermission> existingPermissions = await _dbContext.RolePermissions
                .Where(x => permissionIds.Contains(x.PermissionId) && x.RoleId == roleId)
                .ToListAsync();

            // If any existing RolePermissions found, throw an exception
            if (existingPermissions.Count > 0)
            {
                List<Guid>? duplicatedIds = existingPermissions.Select(x => x.PermissionId).ToList();
                throw new ConflictException($"Duplicate permission assignments found for RoleId {roleId}. Duplicated PermissionIds: {string.Join(", ", duplicatedIds)}");
            }

            // Create new RolePermission entries
            IEnumerable<RolePermission> rolePermissions = permissionIds.Select(permissionId => new RolePermission
            {
                RoleId = roleId,
                PermissionId = permissionId
            });

            // Add and save changes
            await _dbContext.RolePermissions.AddRangeAsync(rolePermissions);
            return await _dbContext.SaveChangesAsync() > 0;
        }

        public async Task<IList<Permission>> GetByRoleIdsAsync(IList<Guid> roleIds)
        {
            return await _dbContext.RolePermissions.Where(rolePermission => roleIds.Contains(rolePermission.RoleId))
                                                   .Select(p => p.Permission)
                                                   .Distinct()
                                                   .ToListAsync();
        }

        public async Task<IList<Permission>> GetByRoleNamesIdsAsync(IList<string> roleNames)
        {
            return await _dbContext.RolePermissions.Where(rp => roleNames.Contains(rp.Role.Name ?? string.Empty))
                                                   .Select(p => p.Permission)
                                                   .Distinct()
                                                   .ToListAsync();
        }

        public async Task<bool> RemovePermissionsFromRoleByRoleIdAsync(Guid roleId, IList<Guid>? permissionIds = null)
        {
            if (permissionIds != null && permissionIds.Count > 0)
            {
                return await _dbContext.RolePermissions.Where(x => x.RoleId == roleId && permissionIds.Contains(x.PermissionId)).ExecuteDeleteAsync() > 0;
            }

            return await _dbContext.RolePermissions.Where(x => x.RoleId == roleId).ExecuteDeleteAsync() > 0;
        }
    }
}