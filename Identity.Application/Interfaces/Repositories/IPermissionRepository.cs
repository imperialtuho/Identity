using Identity.Domain.Entities;

namespace Identity.Application.Interfaces.Repositories
{
    public interface IPermissionRepository : IEntityFrameworkGenericRepository<Permission>
    {
        Task<IList<Permission>> GetByRoleIdsAsync(IList<Guid> roleIds);

        Task<IList<Permission>> GetByRoleNamesIdsAsync(IList<string> roleNames);

        Task<bool> RemovePermissionsFromRoleByRoleIdAsync(Guid roleId, IList<Guid>? permissionIds = null);

        Task<bool> AssignToRoleAsync(Guid roleId, IList<Guid> permissionIds);
    }
}