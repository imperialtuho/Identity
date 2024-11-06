using Identity.Application.Dtos;
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
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = Policies.Super)]
        public async Task<IActionResult> GetUserRolesByUserIdAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest($"{nameof(userId)} is required");
            }

            GetUserRolesByIdDto result = await userService.GetUserRolesByIdAsync(userId);

            return Ok(result);
        }

        /// <summary>
        /// Get user by id.
        /// </summary>
        /// <param name="id">The id.</param>
        /// <returns>UserDto.</returns>
        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetByIdAsync([FromRoute] string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest($"{nameof(id)} is required");
            }

            UserDto result = await userService.GetByIdAsync(id);

            return Ok(result);
        }

        /// <summary>
        /// Updates user by id.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <param name="request">The request.</param>
        /// <returns>UserDto model after successfully update action.</returns>
        [HttpPut("{userId}")]
        [Authorize]
        public async Task<IActionResult> UpdateAsync([FromRoute] string userId, [FromBody] UpdateUserRequest request)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest($"{nameof(userId)} is required");
            }

            if (!userId.Equals(request.Id))
            {
                return BadRequest("Id is not matched with request Id");
            }

            UserDto result = await userService.UpdateAsync(userId, request);

            return Ok(result);
        }

        /// <summary>
        /// Updates user's password.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        [HttpPut("{userId}/password")]
        [Authorize]
        public async Task<IActionResult> UpdatePasswordAsync([FromRoute] string userId, [FromBody] string password)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest($"{nameof(userId)} is required");
            }

            bool result = await userService.UpdatePasswordAsync(userId, password);

            return Ok(result);
        }

        [HttpDelete("{userId}")]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = Policies.Delete)]
        public async Task<IActionResult> DeleteAsync([FromRoute] string userId, bool isSoftDelete = true)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest($"{nameof(userId)} is required");
            }

            bool result = await userService.DeleteByIdAsync(userId, isSoftDelete);

            return Ok(result);
        }

        [HttpPost("search")]
        [AllowAnonymous]
        public async Task<IActionResult> SearchAsync([FromBody] SearchRequest? request, bool isIncludeDeletedUser = false)
        {
            if (request == null)
            {
                return BadRequest("search payload is required");
            }

            PaginatedResponse<UserDto> result = await userService.SearchAsync(request, isIncludeDeletedUser);

            return Ok(result);
        }
    }
}