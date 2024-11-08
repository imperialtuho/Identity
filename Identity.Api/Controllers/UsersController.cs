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
    public class UsersController(IUserService userService) : ControllerBase
    {
        /// <summary>
        /// Deletes user by id.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <param name="isSoftDelete">The param which action will be soft or hard delete</param>
        /// <returns>True/False on based on result of the delete action.</returns>
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

        /// <summary>
        /// Gets user by id.
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
        /// Searches user by keyword request.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="isIncludingDeletedUser">Is including deleted user or not.</param>
        /// <returns>Result of searching user by keyword action.</returns>
        [HttpPost("search")]
        [AllowAnonymous]
        public async Task<IActionResult> SearchAsync([FromBody] SearchRequest? request, bool isIncludingDeletedUser = false)
        {
            if (request == null)
            {
                return BadRequest("search payload is required");
            }

            PaginatedResponse<UserDto> result = await userService.SearchAsync(request, isIncludingDeletedUser);

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
        /// <returns>True/False based on updating user's password action.</returns>
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
    }
}