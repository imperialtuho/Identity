using Identity.Application.Dtos.Permission;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// The permission controller.
    /// </summary>
    [ApiVersion("1.0")]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class PermissionsController(IPermissionService permissionService) : BaseController
    {
        [HttpPost]
        [MapToApiVersion(1.0)]
        [Authorize(Roles = $"{SuperAdmin}", Policy = $"{ApplicationPolicies.Full}")]
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
        [MapToApiVersion(1.0)]
        [Authorize(Roles = $"{SuperAdmin}", Policy = $"{ApplicationPolicies.Full}")]
        public async Task<IActionResult> DeleteByIdAsync(Guid id)
        {
            return Result(await permissionService.DeleteByIdAsync(id), HttpStatusCode.OK);
        }

        /// <summary>
        /// Gets permission by id.
        /// </summary>
        /// <param name="id">The id.</param>
        /// <returns>A permission by following the provided id.</returns>
        [HttpGet("{id}")]
        [MapToApiVersion(1.0)]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}")]
        public async Task<IActionResult> GetByIdAsync(Guid id)
        {
            return Result(await permissionService.GetByIdAsync(id));
        }

        /// <summary>
        /// Gets permissions by role ids.
        /// </summary>
        /// <param name="ids">The id.</param>
        /// <returns>A list permissions by following the provided role id.</returns>
        [HttpGet("by-role-ids")]
        [MapToApiVersion(1.0)]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = ApplicationPolicies.Special)]
        public async Task<IActionResult> GetByRoleIdAsync([CsvBinder] IList<string> ids)
        {
            List<Guid>? roleIds = [];

            foreach (string id in ids)
            {
                if (Guid.TryParse(id, out Guid guid) && guid != Guid.Empty)
                {
                    roleIds.Add(guid);
                }
            }

            return Result(await permissionService.GetByRoleIdsAsync(roleIds));
        }

        /// <summary>
        /// Gets permissions by role names.
        /// </summary>
        /// <param name="names">A list of role names.</param>
        /// <returns>A list permissions by following the provided role names.</returns>
        [HttpGet("by-role-names")]
        [MapToApiVersion(1.0)]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}")]
        public async Task<IActionResult> GetByRoleNamesAsync([CsvBinder] IList<string> names)
        {
            return Result(await permissionService.GetByRoleNamesAsync(names));
        }

        /// <summary>
        /// Updates Permission async.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns>Return updated permission.</returns>
        [HttpPut]
        [MapToApiVersion(1.0)]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}")]
        public async Task<IActionResult> UpdateAsync(PermissionUpdateRequest request)
        {
            return Result(await permissionService.UpdateAsync(request), HttpStatusCode.OK);
        }
    }
}