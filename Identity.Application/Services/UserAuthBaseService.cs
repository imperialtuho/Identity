using AutoMapper;
using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Repositories;
using Identity.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Text.RegularExpressions;

namespace Identity.Application.Services
{
    public class UserAuthBaseService
    {
        protected readonly ApplicationSettings _applicationSettings;
        protected readonly IMapper _mapper;
        protected readonly IPasswordHasher<User> _passwordHasher;
        protected readonly IRefreshTokenRepository _refreshTokenRepository;
        protected readonly ITokenRepository _tokenRepository;
        protected readonly UserManager<User> _userManager;
        protected readonly string EmailPattern = @"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$";
        protected readonly string PasswordPattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$";
        private const int NameLength = 1;

        public UserAuthBaseService(UserManager<User> userManager,
            IPasswordHasher<User> passwordHasher,
            IRefreshTokenRepository refreshTokenRepository,
            ITokenRepository tokenRepository,
            IOptions<ApplicationSettings> applicationSettings,
            IMapper mapper)
        {
            _userManager = userManager;
            _passwordHasher = passwordHasher;
            _refreshTokenRepository = refreshTokenRepository;
            _tokenRepository = tokenRepository;
            _applicationSettings = applicationSettings.Value;
            _mapper = mapper;
        }

        protected void ValidateClaims(IList<ClaimDto>? claims)
        {
            if (claims != null && claims.Any(c => string.IsNullOrEmpty(c.Type) || string.IsNullOrEmpty(c.Value)))
            {
                throw new ArgumentException($"Claim type and value must not be empty.");
            }
        }

        protected void ValidateEmail(string? email)
        {
            if (string.IsNullOrEmpty(email))
            {
                throw new ArgumentException($"{nameof(email)} is required.");
            }

            string emailPattern = EmailPattern;

            if (!Regex.IsMatch(email, emailPattern))
            {
                throw new ArgumentException($"Email {email} is invalid");
            }
        }

        protected void ValidatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is required.");
            }

            string passwordPattern = PasswordPattern;

            if (!Regex.IsMatch(password, passwordPattern))
            {
                throw new ArgumentException(@"Password must have at least 8 characters,
                                              at least 1 uppercase letter, at least 1 lowercase letter,
                                              at least 1 digit and at least 1 special character.");
            }
        }

        protected void ValidateRoles(IList<string>? roles)
        {
            IList<string>? allowedRoles = _applicationSettings.AllowedRoles ?? throw new InvalidOperationException($"{nameof(allowedRoles)} setting is null!");

            if (roles != null && roles.Any(registerRole => !allowedRoles.Contains(registerRole)))
            {
                throw new ArgumentException($"Roles must belong to this list: {string.Join(", ", allowedRoles)}.");
            }
        }

        protected void ValidateUser(UserDto user, string password)
        {
            ArgumentNullException.ThrowIfNull(user);

            ValidateEmail(user.Email);
            ValidateUserName(user.UserName);
            ValidatePassword(password);
        }

        protected void ValidateUserName(string? name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"{nameof(name)} is required.");
            }

            if (name.Length < NameLength)
            {
                throw new ArgumentException($"{nameof(name)} must have at least {NameLength} characters.");
            }
        }

        protected async Task ValidateModelAsync(User requestModel, string password)
        {
            ArgumentNullException.ThrowIfNull(requestModel);

            ValidateEmail(requestModel.Email);
            ValidateUserName(requestModel.UserName);
            ValidatePassword(password);

            User? foundUserByEmail = await _userManager.FindByEmailAsync(requestModel.Email);
            User? foundUserByUserName = await _userManager.FindByNameAsync(requestModel.UserName);

            bool isDisplayNameTaken = _userManager.Users.Any(u => u.DisplayName.Equals(requestModel.DisplayName));

            if (foundUserByEmail != null && !requestModel.Id.Equals(foundUserByEmail.Id))
            {
                throw new InvalidOperationException($"A user with email '{requestModel.Email}' already exists. Please try another email.");
            }

            if (foundUserByUserName != null && !requestModel.Id.Equals(foundUserByUserName.Id))
            {
                throw new InvalidOperationException($"A user with username '{requestModel.UserName}' already exists. Please try another username.");
            }

            if (isDisplayNameTaken && (!requestModel.Id.Equals(foundUserByEmail!.Id) || !requestModel.Id.Equals(foundUserByUserName!.Id)))
            {
                throw new InvalidOperationException($"The display name '{requestModel.DisplayName}' is already taken. Please try another display name.");
            }
        }
    }
}