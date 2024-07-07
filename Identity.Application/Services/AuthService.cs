using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Repositories;
using Identity.Application.Interfaces.Services;
using Identity.Domain.Common;
using Identity.Domain.Constants;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using IdentityAPI.Domain.Constants;
using IdentityAPI.Domain.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;

namespace Identity.Application.Services
{
    public class AuthService : UserAuthBaseService, IAuthService
    {
        public AuthService(UserManager<User> userManager,
            IPasswordHasher<User> passwordHasher,
            ITokenRepository tokenRepository,
            IRefreshTokenRepository refreshTokenRepository,
            IOptions<ApplicationSettings> applicationSettings) : base(userManager, passwordHasher, refreshTokenRepository, tokenRepository, applicationSettings)
        {
        }

        #region Register

        public async Task<TokenDto> RegisterAsync(RegisterDto registerModel)
        {
            User? foundUserByEmail = await _userManager.FindByEmailAsync(registerModel.Email);
            User? foundUserByUserName = await _userManager.FindByNameAsync(registerModel.UserName);

            if (foundUserByEmail != null || foundUserByUserName != null)
            {
                throw new InvalidOperationException($"User with {registerModel.Email} or {registerModel.UserName} exists, please try another email.");
            }

            var userDto = new UserDto
            {
                UserName = registerModel.UserName,
                Email = registerModel.Email
            };

            IList<string>? roles = registerModel.Roles;
            IList<ClaimDto>? claims = registerModel.Claims;

            User newUser = InitializeUser(userDto, registerModel.Roles);

            ValidateUser(userDto, registerModel.Password);
            ValidateRoles(roles);
            ValidateClaims(claims);

            IdentityResult identityResult = await _userManager.CreateAsync(newUser, registerModel.Password);

            if (identityResult == null || !identityResult.Succeeded)
            {
                throw new InvalidCredentialException(ResponseMessage.UnknownError);
            }

            User? appUser = await _userManager.FindByEmailAsync(newUser.Email!) ?? throw new NotFoundException($"User with {newUser.Email} not found!");
            var addingRoles = roles != null && roles.Any() ? roles : [Roles.User];

            await AddRoles(appUser, addingRoles);
            await AddClaims(appUser, claims);

            IList<Claim>? addedClaims = await _userManager.GetClaimsAsync(appUser);

            return await _tokenRepository.CreateTokenAsync(appUser, addingRoles, addedClaims);
        }

        public async Task<bool> RegisterWithEmailConfirmAsync(RegisterDto registerModel)
        {
            User? foundUserByEmail = await _userManager.FindByEmailAsync(registerModel.Email);
            User? foundUserByUserName = await _userManager.FindByNameAsync(registerModel.UserName);

            if (foundUserByEmail != null || foundUserByUserName != null)
            {
                throw new InvalidOperationException($"User with {registerModel.Email} or {registerModel.UserName} exists, please try another email.");
            }

            var userDto = new UserDto
            {
                Email = registerModel.Email,
                UserName = registerModel.UserName,
            };

            IList<string>? roles = registerModel.Roles;
            IList<ClaimDto>? claims = registerModel.Claims;

            User newUser = InitializeUser(userDto, registerModel.Roles);

            ValidateUser(userDto, registerModel.Password);
            ValidateRoles(roles);
            ValidateClaims(claims);

            IdentityResult? identityResult = await _userManager.CreateAsync(newUser, registerModel.Password);

            if (identityResult == null || identityResult.Succeeded)
            {
                throw new UnhandledException(ResponseMessage.UnknownError);
            }

            User? appUser = await _userManager.FindByEmailAsync(newUser.Email!) ?? throw new NotFoundException($"User with {newUser.Email} not found!");
            var addingRoles = roles != null && roles.Any() ? roles : [Roles.User];

            await AddRoles(appUser, addingRoles);
            await AddClaims(appUser, claims);

            string token = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);

            if (string.IsNullOrEmpty(token))
            {
                throw new InvalidCredentialException($"{token} is Null or Empty");
            }

            return EmailHelper.SendEmailTwoFactorCode(appUser.Email, token);
        }

        #endregion Register

        #region Login

        public async Task<TokenDto> LoginAsync(string email, string password)
        {
            ValidateEmail(email);

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty.");
            }

            User? loginUser = await _userManager.FindByEmailAsync(email) ?? throw new InvalidCredentialException(ResponseMessage.InvalidCredentialException);

            bool isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

            if (!isPasswordMatched)
            {
                throw new InvalidCredentialException(ResponseMessage.InvalidCredentialException);
            }

            IList<string> roles = await _userManager.GetRolesAsync(loginUser);
            IList<Claim> claims = await _userManager.GetClaimsAsync(loginUser);

            return await _tokenRepository.CreateTokenAsync(loginUser, roles, claims);
        }

        public async Task<TokenDto> LoginRequireEmailConfirmAsync(string email, string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException(string.Format(ResponseMessage.EmptyOrNullException, nameof(password)));
            }

            ValidateEmail(email);

            User? loginUser = await _userManager.FindByEmailAsync(email) ?? throw new InvalidCredentialException(ResponseMessage.InvalidCredentialException);

            bool isEmailConfirmed = loginUser.EmailConfirmed;

            if (!isEmailConfirmed)
            {
                throw new InvalidCredentialException(ResponseMessage.InvalidCredentialException);
            }

            bool isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

            if (!isPasswordMatched)
            {
                throw new InvalidCredentialException(ResponseMessage.InvalidCredentialException);
            }

            IList<string> roles = await _userManager.GetRolesAsync(loginUser);
            IList<Claim> claims = await _userManager.GetClaimsAsync(loginUser);

            return await _tokenRepository.CreateTokenAsync(loginUser, roles, claims);
        }

        public async Task<bool> LoginWith2FaAsync(string email, string password)
        {
            ValidateEmail(email);

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty.");
            }

            User? loginUser = await _userManager.FindByEmailAsync(email) ?? throw new InvalidCredentialException($"Invalid credential.");

            bool isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

            if (!isPasswordMatched)
            {
                throw new InvalidCredentialException(ResponseMessage.InvalidCredentialException);
            }

            string token = await _userManager.GenerateTwoFactorTokenAsync(loginUser, TokenOptions.DefaultProvider);

            if (string.IsNullOrEmpty(token))
            {
                throw new UnhandledException($"Cannot create token");
            }

            return EmailHelper.SendEmailTwoFactorCode(loginUser.Email!, token);
        }

        public Task<TokenDto> GoogleLogin(ExternalAuthDto externalAuth)
        {
            throw new NotImplementedException();
        }

        #endregion Login

        #region Token

        public async Task<TokenDto> RefreshTokenAsync(TokenDto token)
        {
            ClaimsPrincipal? principal = _tokenRepository.GetPrincipalFromExpiredToken(token.Token) ?? throw new InvalidCredentialException("Invalid token.");
            long tokenExpiryUnix = long.Parse(principal.Claims.Single(p => p.Type == JwtRegisteredClaimNames.Exp).Value);
            DateTime tokenExpiryDate = DateTime.UnixEpoch.AddSeconds(tokenExpiryUnix);


            if (tokenExpiryDate > DateTime.Now)
            {
                throw new InvalidOperationException("The access token has not expired yet.");
            }

            string jti = principal.Claims.Single(p => p.Type == JwtRegisteredClaimNames.Jti).Value;
            RefreshToken? storedRefreshToken = await _refreshTokenRepository.FindByTokenAsync(token.RefreshToken);

            if (storedRefreshToken == null ||
                storedRefreshToken.JwtId != jti ||
                storedRefreshToken.ExpiryDate < DateTime.Now ||
                storedRefreshToken.Invalidated ||
                storedRefreshToken.Used)
            {
                throw new InvalidCredentialException("Invalid refresh token.");
            }

            storedRefreshToken.Used = true;
            _refreshTokenRepository.Update(storedRefreshToken);
            await _refreshTokenRepository.CompleteAsync();

            string? email = principal.Claims.Single(p => p.Type == ClaimTypes.Email).Value;
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException($"User with {email} not found!");
            IList<string> roles = await _userManager.GetRolesAsync(user);
            TokenDto resource = await _tokenRepository.CreateTokenAsync(user, roles);

            return resource;
        }

        public async Task<bool> InvalidateUserTokens(string email)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new ArgumentException($"User with {email} doesn't exist.");

            await _refreshTokenRepository.InvalidateUserTokens(user.Id);
            await _refreshTokenRepository.CompleteAsync();

            return true;
        }

        public async Task<string> Get2FaTokenAsync(string email)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException($"User with {email} is not found");

            string token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultProvider);

            if (string.IsNullOrEmpty(token))
            {
                throw new UnhandledException(ResponseMessage.UnknownError);
            }

            EmailHelper.SendEmailTwoFactorCode(user.Email!, token);

            return token;
        }

        public async Task<TokenDto> Verify2FaTokenAsync(string email, string token)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException($"User with {email} not found!");

            bool verified = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultProvider, token);

            if (!verified)
            {
                throw new ArgumentException("OTP does not match, please try again.");
            }

            IList<string> roles = await _userManager.GetRolesAsync(user);
            IList<Claim> claims = await _userManager.GetClaimsAsync(user);

            return await _tokenRepository.CreateTokenAsync(user, roles, claims);
        }

        public async Task<TokenDto> VerifyEmailTokenAsync(string email, string token)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new NotFoundException($"User with {email} not found!");

            IdentityResult? result = await _userManager.ConfirmEmailAsync(user, token);

            if (result == null || !result.Succeeded)
            {
                throw new InvalidCredentialException("Email verification failed, please try again.");
            }

            IList<string> roles = await _userManager.GetRolesAsync(user);
            IList<Claim> claims = await _userManager.GetClaimsAsync(user);

            return await _tokenRepository.CreateTokenAsync(user, roles, claims);
        }

        #endregion Token

        #region Add Claims and Roles

        public async Task<bool> AddClaimToUserAsync(string email, string claimType, string claimValue)
        {
            User? user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                IList<string>? allowedClaims = _applicationSettings.AvailableClaimPolicies;

                if (!allowedClaims!.Contains(claimValue))
                {
                    throw new InvalidOperationException($"Invalid Claims or Policy value try again!");
                }

                var claim = new Claim(claimType, claimValue);

                IdentityResult result = await _userManager.AddClaimAsync(user, claim);

                if (result.Succeeded)
                {
                    return true;
                }

                return false;
            }

            throw new ArgumentException("User doesn't exists.");
        }

        public async Task<bool> AddUserToRolesAsync(string email, IList<string> roles)
        {
            User? user = await _userManager.FindByEmailAsync(email) ?? throw new ArgumentException($"User with {email} doesn't exists.");

            ValidateRoles(roles);

            IdentityResult identityResult = await _userManager.AddToRolesAsync(user, roles);

            return identityResult.Succeeded;
        }

        #endregion Add Claims and Roles

        #region Internal Processes

        private async Task AddRoles(User user, IList<string> roles)
        {
            IdentityResult? addRolesResult = await _userManager.AddToRolesAsync(user, roles);

            if (!addRolesResult.Succeeded)
            {
                throw new InvalidDataException("Add roles failed.");
            }
        }

        private async Task AddClaims(User user, IList<ClaimDto>? claimsInput)
        {
            var claims = claimsInput?.Select(c => new Claim(c.Type, c.Value));
            var addClaimsResult = new IdentityResult();

            if (claims != null && claims.Any())
            {
                addClaimsResult = await _userManager.AddClaimsAsync(user, claims);
            }

            if (!addClaimsResult.Succeeded)
            {
                throw new InvalidDataException("Add claims failed.");
            }
        }

        private User InitializeUser(UserDto user, IList<string>? roles)
        {
            string defaultCreatedBy = DefaultRoleValue.User;
            string defaultModifiedBy = DefaultRoleValue.User;

            if (roles?.FirstOrDefault(role => role.Equals(DefaultRoleValue.Admin)) != null)
            {
                defaultCreatedBy = DefaultRoleValue.SuperAdmin;
                defaultModifiedBy = DefaultRoleValue.SuperAdmin;
            }

            return new User
            {
                UserName = user.UserName,
                Email = user.Email,
                CreatedBy = defaultCreatedBy,
                ModifiedBy = defaultModifiedBy,
            };
        }

        #endregion Internal Processes
    }
}