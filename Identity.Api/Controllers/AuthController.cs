using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// Controller responsible for authentication operations such as login and registration.
    /// </summary>
    /// <remarks>
    /// Supports API versioning through the route pattern <c>api/v{version}/[controller]</c>.
    /// </remarks>
    [ApiVersion("1.0")]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class AuthController(IAuthService authSerivce) : BaseController
    {
        /// <summary>
        /// Authenticates a user using email and password.
        /// </summary>
        /// <param name="model">The login information including email and password.</param>
        /// <param name="isEmailConfirmRequired">
        /// If <c>true</c>, login will only succeed if the email is confirmed.
        /// Otherwise, standard login logic is applied.
        /// </param>
        /// <returns>
        /// A 200 OK response with a valid <see cref="TokenDto"/> if authentication is successful.
        /// </returns>
        /// <response code="200">Returns the token if login is successful.</response>
        /// <response code="400">Returns validation errors or invalid credentials.</response>
        /// <remarks>
        /// - When <paramref name="isEmailConfirmRequired"/> is true, the method will ensure that the user's email has been confirmed before issuing a token.
        /// - Otherwise, a standard login flow is used.
        /// </remarks>
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
        /// Registers a new user with optional email confirmation.
        /// </summary>
        /// <param name="model">The registration details including email, password, roles, and claims.</param>
        /// <param name="isEmailConfirmRequired">
        /// If <c>true</c>, user registration will send a confirmation token and return a boolean result.
        /// Otherwise, a <see cref="TokenDto"/> is returned upon successful registration.
        /// </param>
        /// <returns>
        /// A 201 Created response with either <see cref="TokenDto"/> or <c>true</c> indicating that confirmation is required.
        /// </returns>
        /// <response code="201">Returns token or confirmation status if registration is successful.</response>
        /// <response code="400">Returns if registration fails due to invalid data or constraints.</response>
        /// <remarks>
        /// - Validates the user input and assigns default roles and claims as necessary.
        /// - If email confirmation is required, an email is sent with a token instead of returning an access token immediately.
        /// </remarks>
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
    }
}