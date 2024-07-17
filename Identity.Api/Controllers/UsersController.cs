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
        /// <returns>System.Task{ActionResult}.</returns>
        [HttpPost("{userId}/roles")]
        [Authorize($"{SuperAdmin}")]
        public async Task<ActionResult> AddRoleToUserAsync([FromRoute] string userId, [FromBody] RoleDto request)
        {
            try
            {
                return Ok(await authService.AddUserToRolesAsync(userId, request.Email, request.Roles));
            }
            catch (Exception ex)
            {
                throw new UnhandledException(ex.Message);
            }
        }

        [HttpGet("{userId}/roles")]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = "All")]
        public async Task<ActionResult> GetUserRolesByUserIdAsync(string userId)
        {
            try
            {
                return Ok(await userService.GetUserRolesByIdAsync(userId));
            }
            catch (Exception ex)
            {
                throw new UnhandledException(ex.Message);
            }
        }
    }
}