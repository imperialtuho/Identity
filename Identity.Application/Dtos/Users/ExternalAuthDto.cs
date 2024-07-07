namespace Identity.Application.Dtos.Users
{
    public class ExternalAuthDto
    {
        public string? Provider { get; set; }

        public string? IdToken { get; set; }
    }
}