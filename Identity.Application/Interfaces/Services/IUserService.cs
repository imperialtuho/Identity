using Identity.Application.Dtos;
using Identity.Application.Dtos.Users;
using Identity.Domain.Common;

namespace Identity.Application.Interfaces.Services
{
    public interface IUserService
    {
        Task<bool> DeleteByIdAsync(string id, bool isSoftDelete = true);

        Task<IList<UserDto>> GetAllAsync();

        Task<UserDto> GetByEmailAsync(string email);

        Task<UserDto> GetByIdAsync(string id);

        Task<GetUserRolesByIdDto> GetUserRolesByIdAsync(string userId);

        Task<bool> ResendVerificationEmail(string email);

        Task<bool> ResetPasswordAsync(string currentEmail, string password, string token);

        Task<bool> SendResetPasswordEmailAsync(string email);

        Task<UserDto> UpdateAsync(string userId, UpdateUserRequest request);

        Task<bool> UpdatePasswordAsync(string id, string newPassword);

        Task<PaginatedResponse<UserDto>> SearchAsync(SearchRequest request, bool isIncludeDeletedUser = false);
    }
}