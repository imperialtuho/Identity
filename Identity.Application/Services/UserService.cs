using AutoMapper;
using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Repositories;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Identity.Domain.Helpers;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Identity.Application.Services
{
    public class UserService : UserAuthBaseService, IUserService
    {
        public UserService(UserManager<User> userManager,
            IPasswordHasher<User> passwordHasher,
            ITokenRepository tokenRepository,
            IRefreshTokenRepository refreshTokenRepository,
            IOptions<ApplicationSettings> applicationSettings,
            IMapper mapper) : base(userManager, passwordHasher, refreshTokenRepository, tokenRepository, applicationSettings, mapper)
        {
        }

        public async Task<bool> DeleteByIdAsync(string id)
        {
            User? currentUser = await _userManager.FindByIdAsync(id) ?? throw new NotFoundException($"User with {id} not found!");

            IdentityResult identityResult = await _userManager.DeleteAsync(currentUser);

            return identityResult.Succeeded;
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

        public async Task<bool> UpdatePasswordAsync(string id, string newPassword)
        {
            User? currentUser = await _userManager.FindByIdAsync(id) ?? throw new NotFoundException($"User with id: {id} not found!");

            ValidatePassword(newPassword);

            currentUser.PasswordHash = _passwordHasher.HashPassword(currentUser, newPassword);

            IdentityResult? identityResult = await _userManager.UpdateAsync(currentUser);

            if (identityResult == null || !identityResult.Succeeded)
            {
                return false;
            }

            return true;
        }

        public async Task<GetUserRolesByIdDto> GetUserRolesByIdAsync(string userId)
        {
            User? user = await _userManager.FindByIdAsync(userId) ?? throw new NotFoundException($"User with id: {userId} could not be found!");

            IList<string> roles = await _userManager.GetRolesAsync(user);

            return new GetUserRolesByIdDto
            {
                Id = user.Id.ToString(),
                Name = user.UserName!,
                Email = user.Email!,
                Roles = roles
            };
        }
    }
}