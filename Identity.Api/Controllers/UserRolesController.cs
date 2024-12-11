﻿using Identity.Application.Dtos.Users;
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
        /// Adds roles.
        /// </summary>
        /// <param name="userId">The userId.</param>
        /// <param name="request">The request.</param>
        /// <returns>System.Task{IActionResult}.</returns>
        [HttpPost("{userId}/roles")]
        [Authorize(Roles = $"{SuperAdmin}, {Admin}", Policy = $"{ApplicationPolicies.Super}, {ApplicationPolicies.Read}, {ApplicationPolicies.Write}")]
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