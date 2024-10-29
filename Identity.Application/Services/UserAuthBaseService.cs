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
        protected readonly UserManager<User> _userManager;
        protected readonly IPasswordHasher<User> _passwordHasher;
        protected readonly IRefreshTokenRepository _refreshTokenRepository;
        protected readonly ITokenRepository _tokenRepository;
        protected readonly ApplicationSettings _applicationSettings;
        protected readonly IMapper _mapper;

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

        private const int NAME_LENGTH = 1;

        protected void ValidateRoles(IList<string>? roles)
        {
            IList<string>? allowedRoles = _applicationSettings.AllowedRoles ?? throw new InvalidOperationException($"{nameof(allowedRoles)} setting is null!");

            if (roles != null && roles.Any(registerRole => !allowedRoles.Contains(registerRole)))
            {
                throw new ArgumentException($"Roles must belong to this list: {string.Join(", ", allowedRoles)}.");
            }
        }

        protected void ValidateClaims(IList<ClaimDto>? claims)
        {
            if (claims != null && claims.Any(c => string.IsNullOrEmpty(c.Type) || string.IsNullOrEmpty(c.Value)))
            {
                throw new ArgumentException($"Claim type and value must not be empty.");
            }
        }

        protected void ValidateUser(UserDto user, string password)
        {
            ArgumentNullException.ThrowIfNull(user);

            ValidateEmail(user.Email);
            ValidateUserName(user.UserName);
            ValidatePassword(password);
        }

        protected void ValidateUserName(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("Name is required.");
            }

            if (name.Length < NAME_LENGTH)
            {
                throw new ArgumentException($"Name must have at least {NAME_LENGTH} characters.");
            }
        }

        protected void ValidateEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                throw new ArgumentException("Email is required.");
            }

            string emailPattern = @"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$";

            if (!Regex.IsMatch(email, emailPattern))
            {
                throw new ArgumentException("Invalid email.");
            }
        }

        protected void ValidatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is required.");
            }

            string passwordPattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$";

            if (!Regex.IsMatch(password, passwordPattern))
            {
                throw new ArgumentException("Password must have at least 8 characters, " +
                    "at least 1 uppercase letter, at least 1 lowercase letter, " +
                    "at least 1 digit and at least 1 special character.");
            }
        }
    }
}