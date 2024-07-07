using Identity.Application.Dtos.Users;

namespace Identity.Application.Interfaces.Services
{
    public interface IUserService
    {
        Task<UserDto> GetByEmailAsync(string email);

        Task<UserDto> GetByIdAsync(string id);

        Task<IList<UserDto>> GetAllAsync();

        Task<bool> UpdatePasswordAsync(string id, string newPassword);

        Task<bool> SendResetPasswordEmailAsync(string email);

        Task<bool> ResetPasswordAsync(string currentEmail, string password, string token);

        Task<bool> ResendVerificationEmail(string email);

        Task<bool> DeleteByIdAsync(string id);

        Task<GetUserRolesByIdDto> GetUserRolesByIdAsync(string userId);
    }
}