using Identity.Application.Dtos.Permission;

namespace Identity.Application.Interfaces.Services
{
    public interface IPermissionService
    {
        Task<PermissionResponse> GetByIdAsync(string id);

        Task<IList<PermissionResponse>> GetByRoleIdAsync(string id);

        Task<PermissionResponse> AddAsync(PermissionAddRequest request);

        Task<PermissionResponse> UpdateAsync(PermissionUpdateRequest request);

        Task<bool> DeleteByIdAsync(string id);
    }
}