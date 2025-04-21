using Identity.Application.Dtos;

namespace Identity.Application.Interfaces.Services
{
    public interface IRoleService
    {
        Task<bool> AddAsync(string name);

        Task<IList<RoleDto>> GetAllAsync();

        Task<bool> DeleteByIdAsync(Guid id);

        Task<bool> AssignPermissionsAsync(Guid id, IList<Guid> permissionIds);

        Task<bool> UnAssignPermissionsAsync(Guid id, IList<Guid> permissionIds);

        Task<RolePermissionDto> GetPermissionsByRoleIdAsync(Guid roleId);
    }
}