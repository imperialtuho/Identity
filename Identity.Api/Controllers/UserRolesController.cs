using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public class UserRolesController(IAuthService authService) : ControllerBase
    {
        /// <summary>
        /// Adds roles.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <param name="request">The request.</param>
        /// <returns>System.Task{IActionResult}.</returns>
        [HttpPost("{userId}/roles")]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = $"{Policies.Super}, {Policies.Create}, {Policies.Update}")]
        public async Task<IActionResult> AddRoleToUserAsync([FromRoute] string userId, [FromBody] RoleDto request)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest($"{nameof(userId)} is required");
            }

            return Ok(await authService.AddUserToRolesAsync(userId, request.Email, request.Roles));
        }

        /// <summary>
        /// Gets user roles by user id.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <returns>GetUserRolesByIdDto.</returns>
        [HttpGet("{userId}/roles")]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = $"{Policies.Super}, {Policies.Read}")]
        public async Task<IActionResult> GetUserRolesByUserIdAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest($"{nameof(userId)} is required");
            }

            GetUserRolesByIdDto result = await authService.GetUserRolesByIdAsync(userId);

            return Ok(result);
        }
    }
}