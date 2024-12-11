﻿using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// Authorization Controller constructor.
    /// </summary>
    /// <param name="authSerivce">The authService.</param>
    [ApiVersion("1.0")]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class AuthController(IAuthService authSerivce) : BaseController
    {
        /// <summary>
        /// Login.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns>System.Task{IActionResult}.</returns>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginAsync([FromBody] LoginDto model, [FromQuery] bool isEmailConfirmRequired)
        {
            if (isEmailConfirmRequired)
            {
                return Result(await authSerivce.LoginRequireEmailConfirmAsync(model.Email, model.Password), HttpStatusCode.OK);
            }

            return Result(await authSerivce.LoginAsync(model.Email, model.Password), HttpStatusCode.OK);
        }

        /// <summary>
        /// Registers user.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns>System.Task{IActionResult}.</returns>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterDto model, bool isEmailConfirmRequired)
        {
            if (isEmailConfirmRequired)
            {
                return Result(await authSerivce.RegisterWithEmailConfirmAsync(model), HttpStatusCode.Created);
            }

            return Result(await authSerivce.RegisterAsync(model), HttpStatusCode.Created);
        }

        /// <summary>
        /// Refreshes JWT token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>System.Task{IActionResult}.</returns>
        [HttpPost("refresh-token")]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshTokenAsync([FromBody] TokenDto token)
        {
            return Result(await authSerivce.RefreshTokenAsync(token), HttpStatusCode.OK);
        }
    }
}