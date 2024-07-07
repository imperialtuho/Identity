using Identity.Application.Dtos.Users;

namespace Identity.Application.Interfaces.Services
{
    public interface IAuthService
    {
        Task<TokenDto> RegisterAsync(RegisterDto registerModel);

        Task<bool> RegisterWithEmailConfirmAsync(RegisterDto registerModel);

        Task<TokenDto> LoginAsync(string email, string password);

        Task<TokenDto> LoginRequireEmailConfirmAsync(string email, string password);

        Task<bool> LoginWith2FaAsync(string email, string password);

        Task<TokenDto> GoogleLogin(ExternalAuthDto externalAuth);

        Task<bool> AddUserToRolesAsync(string email, IList<string> roles);

        Task<bool> AddClaimToUserAsync(string email, string claimType, string claimValue);

        Task<TokenDto> RefreshTokenAsync(TokenDto token);

        Task<bool> InvalidateUserTokens(string email);

        Task<string> Get2FaTokenAsync(string email);

        Task<TokenDto> Verify2FaTokenAsync(string email, string token);

        Task<TokenDto> VerifyEmailTokenAsync(string email, string token);

    }
}