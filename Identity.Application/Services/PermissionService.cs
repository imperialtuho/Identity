using AutoMapper;
using Identity.Application.Dtos.Permission;
using Identity.Application.Interfaces.Repositories;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Mapster;

namespace Identity.Application.Services
{
    public class PermissionService(IPermissionRepository permissionRepository, IMapper mapper) : IPermissionService
    {
        public async Task<PermissionDto> AddAsync(PermissionAddRequest request)
        {
            Permission permissionToAdd = request.Adapt<Permission>();

            Permission result = await permissionRepository.AddWithSaveChangesAndReturnModelAsync(permissionToAdd);

            return result.Adapt<PermissionDto>();
        }

        public async Task<bool> DeleteByIdAsync(Guid id)
        {
            Permission currentPermission = await permissionRepository.GetByIdAsync(id) ?? throw new NotFoundException($"{nameof(Permission)} with provided id: {id} is not found.");

            return await permissionRepository.ForceDeleteAsync(currentPermission);
        }

        public async Task<PermissionDto> GetByIdAsync(Guid id)
        {
            Permission result = await permissionRepository.GetByIdAsync(id);

            return result.Adapt<PermissionDto>();
        }

        public async Task<IList<PermissionDto>> GetByRoleNamesAsync(IList<string> names)
        {
            return mapper.Map<IList<PermissionDto>>(await permissionRepository.GetByRoleNamesIdsAsync(names));
        }

        public async Task<IList<PermissionDto>> GetByRoleIdsAsync(IList<Guid> roleIds)
        {
            IList<Permission> permissions = await permissionRepository.GetByRoleIdsAsync(roleIds);

            return permissions.Adapt<IList<PermissionDto>>();
        }

        public async Task<PermissionDto> UpdateAsync(PermissionUpdateRequest request)
        {
            Permission currentPermission = await permissionRepository.GetByIdAsync(request.Id)
                                        ?? throw new NotFoundException($"{nameof(Permission)} with provided id: {request.Id} is not found.");

            currentPermission = request.Adapt(currentPermission);

            Permission result = await permissionRepository.UpdateWithSaveChangesAndReturnModelAsync(currentPermission);

            return result.Adapt<PermissionDto>();
        }

        public async Task<bool> RemovePermissionsFromRoleByRoleIdAsync(Guid roleId, IList<Guid>? permissionIds = null)
        {
            return await permissionRepository.RemovePermissionsFromRoleByRoleIdAsync(roleId, permissionIds);
        }

        public async Task<bool> AssignToRoleAsync(Guid roleId, IList<Guid> permissionIds)
        {
            return await permissionRepository.AssignToRoleAsync(roleId, permissionIds);
        }
    }
}