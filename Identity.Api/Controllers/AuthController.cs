﻿using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public class AuthController(IAuthService authSerivce) : ControllerBase
    {
        /// <summary>
        /// Login.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns>System.Task{ActionResult}.</returns>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult> LoginAsync([FromBody] LoginDto model, [FromQuery] bool isEmailConfirmRequired)
        {
            if (isEmailConfirmRequired)
            {
                return Ok(await authSerivce.LoginRequireEmailConfirmAsync(model.Email, model.Password));
            }

            return Ok(await authSerivce.LoginAsync(model.Email, model.Password));
        }

        /// <summary>
        /// Registers user.
        /// </summary>
        /// <param name="model">The model.</param>
        /// <returns>System.Task{ActionResult}.</returns>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<ActionResult> RegisterAsync([FromBody] RegisterDto model, bool isEmailConfirmRequired)
        {
            if (isEmailConfirmRequired)
            {
                return Ok(await authSerivce.RegisterWithEmailConfirmAsync(model));
            }

            return Ok(await authSerivce.RegisterAsync(model));
        }

        /// <summary>
        /// Refreshes JWT token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>System.Task{ActionResult}.</returns>
        [HttpPost("refresh-token")]
        [AllowAnonymous]
        public async Task<ActionResult> RefreshTokenAsync([FromBody] TokenDto token)
        {
            return Ok(await authSerivce.RefreshTokenAsync(token));
        }
    }
}