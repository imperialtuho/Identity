using Identity.Application.Dtos.Users;

namespace Identity.Application.Interfaces.Services
{
    public interface IAuthService
    {
        Task<bool> AssignClaimsAsync(Guid userId, string email, IList<ClaimDto> claims);

        Task<bool> AssignRolesAsync(Guid userId, IList<string> roles);

        Task<bool> UnAssignRolesAsync(Guid userId, IList<string> roles);

        Task<GetUserRolesByIdDto> GetUserRolesByIdAsync(Guid userId);

        Task<TokenDto> GoogleLogin(ExternalAuthDto externalAuth);

        Task<TokenDto> LoginAsync(string email, string password);

        Task<TokenDto> LoginRequireEmailConfirmAsync(string email, string password);

        Task<bool> LoginWith2FaAsync(string email, string password);

        Task<TokenDto> RegisterAsync(RegisterDto registerModel);

        Task<bool> RegisterWithEmailConfirmAsync(RegisterDto registerModel);
    }
}