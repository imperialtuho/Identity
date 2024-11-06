namespace Identity.Application.Configurations.Settings
{
    public class ApplicationSettings
    {
        public string? BaseUrl { get; set; }

        public string? ProviderName { get; set; }

        public string Password { get; set; }

        public bool IsProductionMode { get; set; }
    }
}