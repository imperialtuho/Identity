using AutoMapper;
using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Repositories;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Common;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Identity.Domain.Helpers;
using Mapster;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Identity.Application.Services
{
    public class UserService : UserAuthBaseService, IUserService
    {
        public UserService(UserManager<User> userManager,
            RoleManager<Role> roleManager,
            IPasswordHasher<User> passwordHasher,
            ITokenRepository tokenRepository,
            IRefreshTokenRepository refreshTokenRepository,
            IOptions<ApplicationSettings> applicationSettings,
            IMapper mapper,
            IHttpContextAccessor httpContextAccessor) : base(userManager, roleManager, passwordHasher, refreshTokenRepository, tokenRepository, applicationSettings, mapper, httpContextAccessor)
        {
        }

        public async Task<bool> DeleteByIdAsync(string id, bool isSoftDelete = true)
        {
            User? currentUser = await _userManager.FindByIdAsync(id) ?? throw new NotFoundException($"User with {id} not found!");

            if (!isSoftDelete)
            {
                IdentityResult identityResult = await _userManager.DeleteAsync(currentUser);

                return identityResult.Succeeded;
            }

            currentUser.IsDeleted = true;

            return (await _userManager.UpdateAsync(currentUser)).Succeeded;
        }

        public async Task<IList<UserDto>> GetAllAsync()
        {
            IList<User> users = await _userManager.Users.ToListAsync();
            return users.Adapt<IList<UserDto>>();
        }

        public async Task<UserDto> GetByEmailAsync(string email)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException($"User with {email} not found!");

            return user.Adapt<UserDto>();
        }

        public async Task<UserDto> GetByIdAsync(string id)
        {
            User? user = await _userManager.FindByIdAsync(id) ?? throw new NotFoundException($"User with {id} not found!");

            return user.Adapt<UserDto>();
        }

        public async Task<bool> ResendVerificationEmail(string email)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new ArgumentException($"User with {email} doesn't exist.");

            string? token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            if (token != null)
            {
                return EmailHelper.SendEmailTwoFactorCode(user.Email, token);
            }

            return false;
        }

        public async Task<bool> ResetPasswordAsync(string currentEmail, string password, string token)
        {
            User? user = await _userManager.FindByEmailAsync(currentEmail) ?? throw new ArgumentException($"User with {currentEmail} doesn't exist.");

            ValidatePassword(password);

            IdentityResult? result = await _userManager.ResetPasswordAsync(user, token, password);

            if (result == null || !result.Succeeded)
            {
                throw new ArgumentException("Reset password failed, please try again.");
            }

            return true;
        }

        public async Task<PaginatedResponse<UserDto>> SearchAsync(SearchRequest request, bool isIncludeDeletedUser = false)
        {
            string keyword = request.Keyword ?? string.Empty;

            IQueryable<User> query = _userManager.Users.AsQueryable();

            Func<IQueryable<User>, IQueryable<User>>? predicate = null;

            if (!string.IsNullOrEmpty(keyword))
            {
                predicate = (user) => user.Where(x => x.DisplayName.Contains(keyword)
                                                   || x.FirstName.Contains(keyword)
                                                   || x.LastName.Contains(keyword));

                query = predicate(query);
            }

            return await PaginatedResponse<UserDto>.CreateAsync(query.Adapt<IQueryable<UserDto>>(), request.PageIndex, request.PageSize);
        }

        public async Task<bool> SendResetPasswordEmailAsync(string email)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new ArgumentException($"User with {email} doesn't exist.");

            string token = await _userManager.GeneratePasswordResetTokenAsync(user);

            if (token != null)
            {
                return EmailHelper.SendEmailTwoFactorCode(user.Email, token);
            }

            return false;
        }

        public async Task<UserDto> UpdateAsync(string userId, UpdateUserRequest request)
        {
            User? currentUser = await _userManager.FindByIdAsync(userId) ?? throw new NotFoundException($"User with id: {userId} not found!");

            currentUser = request.Adapt(currentUser);

            await ValidateModelAsync(requestModel: currentUser, password: string.Empty, isUpdate: true);

            currentUser.ModifiedBy = !string.IsNullOrEmpty(LoginSession?.Email) ? LoginSession.Email : currentUser.ModifiedBy;
            currentUser.ModifiedDate = DateTime.UtcNow;

            IdentityResult? updateResult = await _userManager.UpdateAsync(currentUser);

            if (updateResult != null && updateResult.Succeeded)
            {
                return currentUser.Adapt<UserDto>();
            }

            throw new UnhandledException(updateResult?.ToString());
        }

        public async Task<bool> UpdatePasswordAsync(string id, string newPassword)
        {
            User? currentUser = await _userManager.FindByIdAsync(id) ?? throw new NotFoundException($"User with id: {id} not found!");

            ValidatePassword(newPassword);

            currentUser.PasswordHash = _passwordHasher.HashPassword(currentUser, newPassword);
            currentUser.ModifiedBy = !string.IsNullOrEmpty(LoginSession?.Email) ? LoginSession.Email : currentUser.ModifiedBy;
            currentUser.ModifiedDate = DateTime.UtcNow;

            IdentityResult? identityResult = await _userManager.UpdateAsync(currentUser) ?? new();

            return identityResult.Succeeded;
        }
    }
}