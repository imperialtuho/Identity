using Identity.Application.Dtos.Permission;
using Identity.Application.Interfaces.Repositories;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Mapster;

namespace Identity.Application.Services
{
    public class PermissionService(IPermissionRepository permissionRepository) : IPermissionService
    {
        public async Task<PermissionResponse> AddAsync(PermissionAddRequest request)
        {
            Permission permissionToAdd = request.Adapt<Permission>();

            Permission result = await permissionRepository.AddWithSaveChangesAndReturnModelAsync(permissionToAdd);

            return result.Adapt<PermissionResponse>();
        }

        public async Task<bool> DeleteByIdAsync(string id)
        {
            bool isValidGuid = Guid.TryParse(id, out Guid permissionId);

            if (!isValidGuid)
            {
                throw new ArgumentException("Please provide a valid id.");
            }

            Permission currentPermission = await permissionRepository.GetEntityByIdAsync(permissionId)
                ?? throw new NotFoundException($"{nameof(Permission)} with provided id: {permissionId} is not found.");

            return await permissionRepository.DeleteAndSaveChangesAsync(currentPermission);
        }

        public async Task<PermissionResponse> GetByIdAsync(string id)
        {
            bool isValidGuid = Guid.TryParse(id, out Guid permissionId);

            if (!isValidGuid)
            {
                throw new ArgumentException("Please provide a valid id.");
            }

            Permission result = await permissionRepository.GetEntityByIdAsync(permissionId);

            return result.Adapt<PermissionResponse>();
        }

        public async Task<IList<PermissionResponse>> GetByRoleIdAsync(string id)
        {
            _ = Guid.TryParse(id, out Guid roleId);

            IList<Permission> permissions = await permissionRepository.GetByRoleIdAsync(roleId);

            return permissions.Adapt<IList<PermissionResponse>>();
        }

        public async Task<PermissionResponse> UpdateAsync(PermissionUpdateRequest request)
        {
            Permission currentPermission = await permissionRepository.GetEntityByIdAsync(request.Id)
                                        ?? throw new NotFoundException($"{nameof(Permission)} with provided id: {request.Id} is not found.");

            currentPermission = request.Adapt(currentPermission);

            Permission result = await permissionRepository.UpdateWithSaveChangesAndReturnModelAsync(currentPermission);

            return result.Adapt<PermissionResponse>();
        }
    }
}