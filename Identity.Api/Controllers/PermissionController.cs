using Identity.Application.Dtos.Permission;
using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// The permission controller.
    /// </summary>
    [ApiVersion("1.0")]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class PermissionController(IPermissionService permissionService) : BaseController
    {
        [HttpPost]
        [Authorize(Roles = $"{SuperAdmin}", Policy = $"{ApplicationPolicies.Super}")]
        public async Task<IActionResult> AddAsync(PermissionAddRequest request)
        {
            return Result(await permissionService.AddAsync(request), HttpStatusCode.Created);
        }

        /// <summary>
        /// Deletes permission by id.
        /// </summary>
        /// <param name="id">The id.</param>
        /// <returns>True/False based on delete action.</returns>
        [HttpDelete("{id}")]
        [Authorize(Roles = $"{SuperAdmin}", Policy = $"{ApplicationPolicies.Super}")]
        public async Task<IActionResult> DeleteByIdAsync(string id)
        {
            return Result(await permissionService.DeleteByIdAsync(id), HttpStatusCode.OK);
        }

        /// <summary>
        /// Gets permission by id.
        /// </summary>
        /// <param name="id">The id.</param>
        /// <returns>A permission by following the provided id.</returns>
        [HttpGet("{id}")]
        public async Task<IActionResult> GetByIdAsync(string id)
        {
            return Result(await permissionService.GetByIdAsync(id));
        }

        /// <summary>
        /// Gets permission by role id.
        /// </summary>
        /// <param name="id">The id.</param>
        /// <returns>A list permissions by following the provided role id.</returns>
        [HttpGet("by-role/{id}")]
        public async Task<IActionResult> GetByRoleIdAsync(string id)
        {
            return Result(await permissionService.GetByRoleIdAsync(id));
        }

        /// <summary>
        /// Updates Permission async.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns>Return updated permission.</returns>
        [HttpPut]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = $"{ApplicationPolicies.Super}, {ApplicationPolicies.Write}")]
        public async Task<IActionResult> UpdateAsync(PermissionUpdateRequest request)
        {
            return Result(await permissionService.UpdateAsync(request), HttpStatusCode.OK);
        }
    }
}