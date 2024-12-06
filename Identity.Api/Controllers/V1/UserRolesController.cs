using Asp.Versioning;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers.V1
{
    /// <summary>
    /// The UserRolesController constructor.
    /// </summary>
    /// <param name="authService">The authService.</param>
    public class UserRolesController(IAuthService authService) : BaseV1Controller
    {
        /// <summary>
        /// Adds roles.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <param name="request">The request.</param>
        /// <returns>System.Task{IActionResult}.</returns>
        [HttpPost("{userId}/roles")]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = $"{ApplicationPolicies.Super}, {ApplicationPolicies.Create}, {ApplicationPolicies.Update}")]
        public async Task<IActionResult> AddRoleToUserAsync([FromRoute] string userId, [FromBody] RoleDto request)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest($"{nameof(userId)} is required");
            }

            return Result(await authService.AddUserToRolesAsync(userId, request.Email, request.Roles), HttpStatusCode.Created);
        }

        /// <summary>
        /// Gets user roles by user id.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <returns>GetUserRolesByIdDto.</returns>
        [HttpGet("{userId}/roles")]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = $"{ApplicationPolicies.Super}, {ApplicationPolicies.Read}")]
        public async Task<IActionResult> GetUserRolesByUserIdAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest($"{nameof(userId)} is required");
            }

            GetUserRolesByIdDto result = await authService.GetUserRolesByIdAsync(userId);

            return Result(result, HttpStatusCode.OK);
        }
    }
}