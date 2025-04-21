using Identity.Application.Dtos;
using Identity.Application.Dtos.Users;
using Identity.Domain.Common;

namespace Identity.Application.Interfaces.Services
{
    public interface IUserService
    {
        Task<bool> DeleteByIdAsync(Guid id, bool isSoftDelete = true);

        Task<IList<UserDto>> GetAllAsync();

        Task<UserDto> GetByEmailAsync(string email);

        Task<UserDto> GetByIdAsync(Guid id);

        Task<IList<UserDto>> GetByIdsAsync(IList<Guid> ids);

        Task<bool> ResendVerificationEmail(string email);

        Task<bool> ResetPasswordAsync(string currentEmail, string password, string token);

        Task<bool> SendResetPasswordEmailAsync(string email);

        Task<UserDto> UpdateAsync(Guid userId, UpdateUserRequest request);

        Task<bool> UpdatePasswordAsync(Guid id, string newPassword);

        Task<PaginatedResponse<UserDto>> SearchAsync(SearchRequest request, bool isIncludeDeletedUser = false);
    }
}