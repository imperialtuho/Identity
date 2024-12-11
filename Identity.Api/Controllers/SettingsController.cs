﻿using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos;
using Identity.Domain.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// The SettingsController constructor.
    /// </summary>
    /// <param name="jwtSettings">The jwtSettings.</param>
    [ApiVersion("1.0")]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class SettingsController(IOptions<JwtSettings> jwtSettings) : BaseController
    {
        /// <summary>
        /// Get JWT settings for API consumer.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>JwtSettings.</returns>
        [HttpPost("jwt")]
        [AllowAnonymous]
        public IActionResult GetJwtSettings([FromBody] PasswordDto passwordDto)
        {
            string password = passwordDto.Password;
            string inValidPassword = $"{nameof(password)} is invalid!";

            if (!CheckingHelper.IsBase64String(password))
            {
                return BadRequest(inValidPassword);
            }

            JwtSettings settings = jwtSettings.Value;

            string? decriptedPassword = AesEncryptionHelper.Decrypt(password, settings.Password);

            if (!decriptedPassword.Equals(settings.Password, StringComparison.Ordinal))
            {
                return BadRequest(inValidPassword);
            }

            return Result(settings, HttpStatusCode.OK);
        }
    }
}