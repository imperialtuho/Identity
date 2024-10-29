using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// Users Controller.
    /// </summary>
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController(IAuthService authService, IUserService userService) : ControllerBase
    {
        /// <summary>
        /// Adds roles.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns>System.Task{IActionResult}.</returns>
        [HttpPost("{userId}/roles")]
        [Authorize($"{SuperAdmin}")]
        public async Task<IActionResult> AddRoleToUserAsync([FromRoute] string userId, [FromBody] RoleDto request)
        {
            return Ok(await authService.AddUserToRolesAsync(userId, request.Email, request.Roles));
        }

        /// <summary>
        /// Gets user roles by user id.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <returns>GetUserRolesByIdDto.</returns>
        /// <exception cref="UnhandledException"></exception>
        [HttpGet("{userId}/roles")]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = "All")]
        public async Task<IActionResult> GetUserRolesByUserIdAsync(string userId)
        {
            GetUserRolesByIdDto result = await userService.GetUserRolesByIdAsync(userId);

            return Ok(result);
        }

        /// <summary>
        /// Get user by id.
        /// </summary>
        /// <param name="id">The id.</param>
        /// <returns>UserDto.</returns>
        /// <exception cref="UnhandledException"></exception>
        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetByIdAsync(string id)
        {
            UserDto result = await userService.GetByIdAsync(id);

            return Ok(result);
        }
    }
}