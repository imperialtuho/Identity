namespace Identity.Domain.Exceptions
{
    public sealed class UnhandledException : Exception
    {
        private const string DefaultMessage = "Unexpected error occured.";

        public UnhandledException(string? message = DefaultMessage)
            : base(message)
        {
        }

        public UnhandledException(string? message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }
}