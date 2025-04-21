using Identity.Application.Dtos.Permission;
using Identity.Domain.Entities;

namespace Identity.Application.Interfaces.Services
{
    public interface IPermissionService
    {
        Task<PermissionDto> GetByIdAsync(Guid id);

        Task<IList<PermissionDto>> GetByRoleIdsAsync(IList<Guid> roleIds);

        Task<IList<PermissionDto>> GetByRoleNamesAsync(IList<string> names);

        Task<PermissionDto> AddAsync(PermissionAddRequest request);

        Task<PermissionDto> UpdateAsync(PermissionUpdateRequest request);

        Task<bool> DeleteByIdAsync(Guid id);

        Task<bool> RemovePermissionsFromRoleByRoleIdAsync(Guid roleId, IList<Guid>? permissionIds = null);

        Task<bool> AssignToRoleAsync(Guid roleId, IList<Guid> permissionIds);
    }
}