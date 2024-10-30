using Identity.Domain.Constants;

namespace Identity.Domain.Exceptions
{
    public sealed class UnhandledException : Exception
    {
        public UnhandledException(string? message = ResponseMessage.UnknownError)
            : base(message)
        {
        }

        public UnhandledException(string? message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }
}