namespace Identity.Application.Dtos.Users
{
    public class TokenDto
    {
        public Guid UserId { get; set; }

        public string Token { get; set; }

        public string RefreshToken { get; set; }
    }
}