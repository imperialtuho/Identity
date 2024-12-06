using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers.V1
{
    /// <summary>
    /// Base controller.
    /// </summary>
    [Authorize]
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:ApiVersion}/[controller]")]
    public class BaseV1Controller : ControllerBase
    {
        /// <summary>
        /// Return a result from performing action.
        /// </summary>
        /// <typeparam name="T">The T.</typeparam>
        /// <param name="data">The data will be returned</param>
        /// <param name="statusCode">The status code.</param>
        /// <returns>Return a result after performing controller's action.</returns>
        protected IActionResult Result<T>(T data, HttpStatusCode statusCode = HttpStatusCode.OK)
        {
            return base.StatusCode((int)statusCode, data);
        }
    }
}