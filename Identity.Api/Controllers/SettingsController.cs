using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos;
using Identity.Domain.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SettingsController"/> class with the specified JWT settings.
    /// </summary>
    /// <param name="jwtSettings">
    /// An <see cref="IOptions{JwtSettings}"/> instance containing the configuration settings for JWT authentication.
    /// </param>
    [ApiVersion("1.0")]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class SettingsController(IOptions<JwtSettings> jwtSettings) : BaseController
    {
        /// <summary>
        /// Retrieves the current JWT settings after validating the provided encrypted password.
        /// </summary>
        /// <param name="passwordDto">
        /// A <see cref="PasswordDto"/> containing the Base64-encoded encrypted password to validate the request.
        /// </param>
        /// <returns>
        /// An <see cref="IActionResult"/> containing the JWT settings if the password is valid,
        /// or a <see cref="BadRequestResult"/> if the password is invalid or improperly formatted.
        /// </returns>
        /// <remarks>
        /// This endpoint is anonymous and requires the client to provide a valid, encrypted password (in Base64 format)
        /// to access sensitive JWT configuration details. The encrypted password is decrypted and compared against the configured one.
        /// </remarks>
        [HttpPost("jwt")]
        [MapToApiVersion(1.0)]
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