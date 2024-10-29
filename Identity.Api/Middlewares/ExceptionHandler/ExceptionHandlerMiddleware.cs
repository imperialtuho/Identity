using Microsoft.AspNetCore.Diagnostics;
using Newtonsoft.Json;
using System.Net;
using System.Security.Authentication;

namespace Identity.Api.Middlewares.ExceptionHandler
{
    public static class ExceptionHandlerMiddleware
    {
        public static Action<IApplicationBuilder> CustomExceptionHandlerMiddleware(bool isDevelopment, ILogger logger)
        {
            return applicationBuilder => applicationBuilder.Run(async httpContext =>
            {
                var exceptionHandlerPathFeature = httpContext.Features.Get<IExceptionHandlerPathFeature>();
                Exception specificException = exceptionHandlerPathFeature!.Error;
                logger.LogError($"Api endpoint {exceptionHandlerPathFeature.Path} failed with Unhandled Exception: {JsonConvert.SerializeObject(specificException)}");

                var responseObject = new ExceptionHandlerResponse
                {
                    Status = false,
                    ErrorCode = HttpStatusCode.InternalServerError,
                    Message = specificException.Message,
                    InnerExceptionMessage = specificException.InnerException?.Message,
                    Path = exceptionHandlerPathFeature.Path,
                    StackTrace = isDevelopment ? specificException.StackTrace : string.Empty,
                    Data = specificException.Data
                };

                httpContext.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

                switch (specificException)
                {
                    case NotFoundException _:

                        responseObject.ErrorCode = HttpStatusCode.NotFound;
                        httpContext.Response.StatusCode = (int)(HttpStatusCode.NotFound);
                        break;

                    case InvalidOperationException _:

                        responseObject.ErrorCode = HttpStatusCode.BadRequest;
                        httpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                        break;

                    case AuthenticationException _:

                        responseObject.ErrorCode = HttpStatusCode.Unauthorized;
                        httpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        break;

                    case UnhandledException _:

                        responseObject.ErrorCode = HttpStatusCode.InternalServerError;
                        httpContext.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                        break;
                }

                string result = JsonConvert.SerializeObject(responseObject);
                httpContext.Response.ContentType = "application/json";

                await httpContext.Response.WriteAsync(result);
            }
            );
        }

        public static bool IsProductionEnvironment(IWebHostEnvironment env, string environmentName)
        {
            return env.IsProduction() || environmentName.Contains("Production", StringComparison.OrdinalIgnoreCase);
        }

        public class ExceptionHandlerResponse
        {
            /// <summary>
            /// Unique Identifier used by logging.
            /// </summary>
            public Guid CorrelationId { get; set; } = Guid.NewGuid();

            /// <summary>
            /// The Status.
            /// </summary>
            public bool Status { get; set; } = true;

            /// <summary>
            /// The ErrorCode.
            /// </summary>
            public HttpStatusCode ErrorCode { get; set; }

            /// <summary>
            /// The Message.
            /// </summary>
            public string? Message { get; set; }

            /// <summary>
            /// The inner exception message.
            /// </summary>
            public string? InnerExceptionMessage { get; set; }

            /// <summary>
            /// The error's Path.
            /// </summary>
            public string Path { get; set; }

            /// <summary>
            /// The StackTrace.
            /// </summary>
            public string? StackTrace { get; set; }

            /// <summary>
            /// The Data.
            /// </summary>
            public object? Data { get; set; }
        }
    }
}