using System.Text.Json.Serialization;

namespace Identity.Application.Configurations.Settings
{
    public class JwtSettings
    {
        [JsonIgnore]
        public string Subject { get; set; }

        public string Issuer { get; set; }

        public string Audience { get; set; }

        public string Key { get; set; }

        public bool EnableIdentityUrl { get; set; }

        [JsonIgnore]
        public string TokenValidityInSeconds { get; set; }

        [JsonIgnore]
        public string RefreshTokenValidityInDays { get; set; }

        [JsonIgnore]
        public string Password { get; set; }

        public string Kid { get; set; }
    }
}