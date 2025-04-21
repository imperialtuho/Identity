using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    [ApiVersion(1.0)]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class RolesController(IRoleService roleService) : BaseController
    {
        [HttpPost]
        public async Task<IActionResult> AddAsync([FromBody] string name)
        {
            return Result(await roleService.AddAsync(name), HttpStatusCode.Created);
        }

        [HttpPost("{id}/assign-permissions")]
        public async Task<IActionResult> AssignPermissionsAsync(Guid id, IList<Guid> permissionIds)
        {
            return Result(await roleService.AssignPermissionsAsync(id, permissionIds), HttpStatusCode.OK);
        }

        [HttpPost("{id}/unassign-permissions")]
        public async Task<IActionResult> UnAssignPermissionsAsync(Guid id, IList<Guid> permissionIds)
        {
            return Result(await roleService.UnAssignPermissionsAsync(id, permissionIds), HttpStatusCode.OK);
        }

        [HttpGet]
        [Authorize(Roles = $"{SuperAdmin},{Admin}")]
        public async Task<IActionResult> GetAllAsync()
        {
            return Result(await roleService.GetAllAsync(), HttpStatusCode.OK);
        }

        [HttpGet("{id}/permissions")]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}")]
        public async Task<IActionResult> GetPermissionsByRoleIdAsync(Guid id)
        {
            return Result(await roleService.GetPermissionsByRoleIdAsync(id));
        }
    }
}