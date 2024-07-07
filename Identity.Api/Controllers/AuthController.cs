using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Identity.Api.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public class AuthController(IAuthService authSerivce, IOptions<JwtSettings> jwtSettings) : ControllerBase
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
            try
            {
                if (isEmailConfirmRequired)
                {
                    return Ok(await authSerivce.LoginRequireEmailConfirmAsync(model.Email, model.Password));
                }

                return Ok(await authSerivce.LoginAsync(model.Email, model.Password));
            }
            catch (Exception ex)
            {
                throw new UnhandledException(ex.Message);
            }
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
            try
            {
                if (isEmailConfirmRequired)
                {
                    return Ok(await authSerivce.RegisterWithEmailConfirmAsync(model));
                }

                return Ok(await authSerivce.RegisterAsync(model));
            }
            catch (Exception ex)
            {
                throw new UnhandledException(ex.Message);
            }
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
            try
            {
                return Ok(await authSerivce.RefreshTokenAsync(token));
            }
            catch (Exception ex)
            {
                throw new UnhandledException(ex.Message);
            }
        }

        /// <summary>
        /// Get JWT settings for API consumer.
        /// </summary>
        /// <returns>JwtSettings.</returns>
        [HttpGet("settings")]
        [AllowAnonymous]
        public ActionResult<JwtSettings> GetJwtSettings(string password)
        {

            JwtSettings settings = jwtSettings.Value;

            if (settings == null)
            {
                return NotFound($"{nameof(JwtSettings)} is missing!");
            }

            settings.Key = AesEncryptionHelper.Encrypt(settings.Key, "Jesus");

            return Ok(jwtSettings.Value);
        }
    }
}