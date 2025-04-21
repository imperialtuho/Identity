using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// The UserRolesController constructor.
    /// </summary>
    /// <param name="authService">The authService.</param>
    [ApiVersion("1.0")]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class UserRolesController(IAuthService authService) : BaseController
    {
        /// <summary>
        /// Assign roles to user.
        /// </summary>
        /// <param name="userId">The ID of user.</param>
        /// <param name="roles">The roles to assign.</param>
        /// <returns>System.Task{IActionResult}.</returns>
        [HttpPost("assign/{userId}")]
        [MapToApiVersion(1.0)]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}")]
        public async Task<IActionResult> AssignRoleToUserAsync([FromRoute] Guid userId, IList<string> roles)
        {
            return Result(await authService.AssignRolesAsync(userId, roles), HttpStatusCode.OK);
        }

        /// <summary>
        /// Assign roles to user.
        /// </summary>
        /// <param name="userId">The ID of user.</param>
        /// <param name="roles">The roles to assign.</param>
        /// <returns>System.Task{IActionResult}.</returns>
        [HttpPost("unassign/{userId}")]
        [MapToApiVersion(1.0)]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}")]
        public async Task<IActionResult> UnAssignRoleToUserAsync([FromRoute] Guid userId, IList<string> roles)
        {
            return Result(await authService.UnAssignRolesAsync(userId, roles), HttpStatusCode.OK);
        }

        /// <summary>
        /// Gets user roles by user id.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <returns>GetUserRolesByIdDto.</returns>
        [HttpGet("{userId}")]
        [MapToApiVersion(1.0)]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}")]
        public async Task<IActionResult> GetUserRolesByUserIdAsync(Guid userId)
        {
            GetUserRolesByIdDto result = await authService.GetUserRolesByIdAsync(userId);

            return Result(result, HttpStatusCode.OK);
        }
    }
}