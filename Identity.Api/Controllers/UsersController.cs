using Identity.Application.Dtos;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// Users Controller constructor.
    /// </summary>
    [ApiVersion("1.0")]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class UsersController(IUserService userService) : BaseController
    {
        /// <summary>
        /// Deletes user by id.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <param name="isSoftDelete">The param which action will be soft or hard delete</param>
        /// <returns>True/False on based on result of the delete action.</returns>
        [HttpDelete("{userId}")]
        [MapToApiVersion(1.0)]
        [Authorize]
        public async Task<IActionResult> DeleteAsync([FromRoute] Guid userId, bool isSoftDelete = true)
        {
            return Result(await userService.DeleteByIdAsync(userId, isSoftDelete), HttpStatusCode.OK);
        }

        /// <summary>
        /// Gets user by id.
        /// </summary>
        /// <param name="id">The id.</param>
        /// <returns>UserDto.</returns>
        [HttpGet("{id}")]
        [MapToApiVersion(1.0)]
        [AllowAnonymous]
        public async Task<IActionResult> GetByIdAsync([FromRoute] Guid id)
        {
            return Result(await userService.GetByIdAsync(id), HttpStatusCode.OK);
        }

        /// <summary>
        /// Gets users by ids.
        /// </summary>
        /// <param name="ids">The ids.</param>
        /// <returns>Return a list of users.</returns>
        [HttpGet]
        [MapToApiVersion(1.0)]
        [Authorize]
        public async Task<IActionResult> GetByIdsAsync([CsvBinder] IList<Guid> ids)
        {
            if (ids is null || ids.Count == 0)
            {
                return BadRequest($"{nameof(ids)} is required");
            }

            return Result(await userService.GetByIdsAsync(ids), HttpStatusCode.OK);
        }

        /// <summary>
        /// Searches user by keyword request.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="isIncludingDeletedUser">Is including deleted user or not.</param>
        /// <returns>Result of searching user by keyword action.</returns>
        [HttpPost("search")]
        [MapToApiVersion(1.0)]
        [AllowAnonymous]
        public async Task<IActionResult> SearchAsync([FromBody] SearchRequest? request, bool isIncludingDeletedUser = false)
        {
            if (request == null)
            {
                return BadRequest("search payload is required");
            }

            return Result(await userService.SearchAsync(request, isIncludingDeletedUser), HttpStatusCode.OK);
        }

        /// <summary>
        /// Updates user by id.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <param name="request">The request.</param>
        /// <returns>UserDto model after successfully update action.</returns>
        [HttpPut("{userId}")]
        [MapToApiVersion(1.0)]
        [Authorize]
        public async Task<IActionResult> UpdateAsync([FromRoute] Guid userId, [FromBody] UpdateUserRequest request)
        {
            if (!userId.Equals(request.Id))
            {
                return BadRequest("Id is not matched with request Id");
            }

            return Result(await userService.UpdateAsync(userId, request), HttpStatusCode.OK);
        }

        /// <summary>
        /// Updates user's password.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <param name="password">The password.</param>
        /// <returns>True/False based on updating user's password action.</returns>
        [HttpPut("{userId}/password")]
        [MapToApiVersion(1.0)]
        [Authorize]
        public async Task<IActionResult> UpdatePasswordAsync([FromRoute] Guid userId, [FromBody] string password)
        {
            return Result(await userService.UpdatePasswordAsync(userId, password), HttpStatusCode.OK);
        }
    }
}