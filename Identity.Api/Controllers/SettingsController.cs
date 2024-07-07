﻿using Identity.Application.Configurations.Settings;
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
    [ApiController]
    [Route("api/[controller]")]
    public class SettingsController(IOptions<JwtSettings> jwtSettings) : ControllerBase
    {
        /// <summary>
        /// Get JWT settings for API consumer.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>JwtSettings.</returns>
        [HttpPost("jwt")]
        [AllowAnonymous]
        public ActionResult<JwtSettings> GetJwtSettings([FromBody] string? password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return BadRequest($"{nameof(password)} was not provided!");
            }

            JwtSettings settings = jwtSettings.Value;

            string? decriptedPassword = AesEncryptionHelper.Decrypt(password, settings.Password);

            if (!decriptedPassword.Equals(settings.Password, StringComparison.Ordinal))
            {
                return BadRequest($"{nameof(password)} is invalid!");
            }

            settings.Key = AesEncryptionHelper.Encrypt(settings.Key, password);

            return Ok(jwtSettings.Value);
        }
    }
}