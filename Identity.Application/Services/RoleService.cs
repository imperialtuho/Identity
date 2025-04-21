using AutoMapper;
using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos;
using Identity.Application.Dtos.Permission;
using Identity.Application.Interfaces.Services;
using Identity.Application.Services.Base;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Identity.Application.Services
{
    public class RoleService(UserManager<User> userManager,
        RoleManager<Role> roleManager,
        IPasswordHasher<User> passwordHasher,
        IOptions<ApplicationSettings> applicationSettings,
        IOptions<JwtSettings> jwtSettings, IMapper mapper,
        IHttpContextAccessor httpContextAccessor,
        IPermissionService permissionService) : UserAuthBaseService(userManager, roleManager, passwordHasher, applicationSettings, jwtSettings, mapper, httpContextAccessor), IRoleService
    {
        public async Task<bool> AddAsync(string name)
        {
            if (await _roleManager.RoleExistsAsync(name))
            {
                throw new ConflictException($"Role with name {name} is existed.");
            }

            IdentityResult result = await _roleManager.CreateAsync(new Role(Guid.NewGuid(), name));

            return result.Succeeded;
        }

        public async Task<bool> DeleteByIdAsync(Guid id)
        {
            IList<PermissionDto>? rolePermissions = await permissionService.GetByRoleIdsAsync([id]);

            bool roleRemoved = await _roleManager.Roles.Where(x => x.Id == id).ExecuteDeleteAsync() > 0;

            if (roleRemoved && rolePermissions != null && rolePermissions.Count > 0)
            {
                bool unassignPermissionFromRole = await permissionService.RemovePermissionsFromRoleByRoleIdAsync(id);

                return roleRemoved && unassignPermissionFromRole;
            }

            return roleRemoved;
        }

        public async Task<IList<RoleDto>> GetAllAsync()
        {
            List<Role>? result = await _roleManager.Roles.ToListAsync() ?? [];

            return _mapper.Map<IList<RoleDto>>(result);
        }

        public async Task<bool> AssignPermissionsAsync(Guid id, IList<Guid> permissionIds)
        {
            Role? role = await _roleManager.Roles.FirstOrDefaultAsync(x => x.Id == id) ?? throw new NotFoundException($"Role with id {id} not found.");

            return await permissionService.AssignToRoleAsync(role.Id, permissionIds);
        }

        public async Task<bool> UnAssignPermissionsAsync(Guid id, IList<Guid> permissionIds)
        {
            return await permissionService.RemovePermissionsFromRoleByRoleIdAsync(id);
        }

        public async Task<RolePermissionDto> GetPermissionsByRoleIdAsync(Guid roleId)
        {
            Role? role = await _roleManager.Roles.FirstOrDefaultAsync(x => x.Id == roleId) ?? throw new NotFoundException($"Role with id {roleId} not found.");

            var result = new RolePermissionDto() { RoleId = role.Id, Name = role.Name };

            IList<PermissionDto>? permissionsByRoleId = await permissionService.GetByRoleIdsAsync([roleId]);

            if (permissionsByRoleId != null && permissionsByRoleId.Count > 0)
            {
                result.Permissions = permissionsByRoleId;
            }

            return result;
        }
    }
}