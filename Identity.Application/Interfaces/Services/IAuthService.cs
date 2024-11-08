using Identity.Application.Dtos.Users;

namespace Identity.Application.Interfaces.Services
{
    public interface IAuthService
    {
        Task<bool> AddClaimToUserAsync(string email, string claimType, string claimValue);

        Task<bool> AddUserToRolesAsync(string userId, string email, IList<string> roles);

        Task<GetUserRolesByIdDto> GetUserRolesByIdAsync(string userId);

        Task<string> Get2FaTokenAsync(string email);

        Task<TokenDto> GoogleLogin(ExternalAuthDto externalAuth);

        Task<bool> InvalidateUserTokensAsync(string email);

        Task<TokenDto> LoginAsync(string email, string password);

        Task<TokenDto> LoginRequireEmailConfirmAsync(string email, string password);

        Task<bool> LoginWith2FaAsync(string email, string password);

        Task<TokenDto> RefreshTokenAsync(TokenDto token);

        Task<TokenDto> RegisterAsync(RegisterDto registerModel);

        Task<bool> RegisterWithEmailConfirmAsync(RegisterDto registerModel);

        Task<TokenDto> Verify2FaTokenAsync(string email, string token);

        Task<TokenDto> VerifyEmailTokenAsync(string email, string token);
    }
}