using AutoMapper;
using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos.Users;
using Identity.Application.Interfaces.Services;
using Identity.Application.Services.Base;
using Identity.Domain.Constants;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Identity.Domain.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Authentication;
using System.Security.Claims;

namespace Identity.Application.Services
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthService"/> class.
    /// </summary>
    /// <param name="userManager">The user manager for handling user-related operations.</param>
    /// <param name="roleManager">The role manager for handling role-related operations.</param>
    /// <param name="logger">The logger instance used for logging authentication activities.</param>
    /// <param name="passwordHasher">The password hasher for hashing and verifying passwords.</param>
    /// <param name="applicationSettings">The application settings used for configuration values.</param>
    /// <param name="jwtSettings">The JWT settings used for configuration values.</param>
    /// <param name="mapper">The AutoMapper instance used for object mapping.</param>
    /// <param name="httpContextAccessor">The HTTP context accessor for accessing user and tenant context.</param>
    /// <param name="tokenService">The token service for handling user-related operations.</param>
    /// <exception cref="ArgumentNullException">Thrown if any required dependency is null.</exception>
    public class AuthService(UserManager<User> userManager,
        RoleManager<Role> roleManager,
        ILogger<AuthService> logger,
        IPasswordHasher<User> passwordHasher,
        IOptions<ApplicationSettings> applicationSettings,
        IOptions<JwtSettings> jwtSettings,
        IMapper mapper,
        IHttpContextAccessor httpContextAccessor,
        ITokenService tokenService) : UserAuthBaseService(userManager, roleManager, passwordHasher, applicationSettings, jwtSettings, mapper, httpContextAccessor), IAuthService
    {
        public async Task<GetUserRolesByIdDto> GetUserRolesByIdAsync(Guid userId)
        {
            User? user = await _userManager.FindByIdAsync(userId.ToString()) ?? throw new NotFoundException($"User with id: {userId} could not be found!");

            IList<string> roles = await _userManager.GetRolesAsync(user);

            return new GetUserRolesByIdDto
            {
                Id = user.Id.ToString(),
                Name = user.UserName,
                Email = user.Email,
                Roles = roles
            };
        }

        public async Task<TokenDto> RegisterAsync(RegisterDto registerModel)
        {
            User newUser = await InitializeUser(registerModel);

            await AssignDefaultRoles(newUser);

            return await tokenService.CreateAsync(newUser);
        }

        public async Task<bool> RegisterWithEmailConfirmAsync(RegisterDto registerModel)
        {
            User newUser = await InitializeUser(registerModel);

            await AssignDefaultRoles(newUser);

            string token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

            if (string.IsNullOrEmpty(token))
            {
                throw new InvalidCredentialException($"{token} is Null or Empty");
            }

            return EmailHelper.SendEmailTwoFactorCode(newUser.Email, token);
        }

        /// <summary>
        /// Authenticates a user using the provided email and password, then generates an access token upon successful login.
        /// </summary>
        /// <param name="email">The email address of the user attempting to log in.</param>
        /// <param name="password">The password associated with the specified email.</param>
        /// <returns>
        /// A <see cref="TokenDto"/> object containing the access token and related information.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when the email or password is null, empty, or improperly formatted.
        /// </exception>
        /// <exception cref="InvalidCredentialException">
        /// Thrown when the email does not correspond to a registered user or the password is incorrect.
        /// </exception>
        /// <remarks>
        /// This method performs the following operations:
        /// <list type="bullet">
        /// <item>Validates the email format and ensures the password is not null or empty.</item>
        /// <item>Retrieves the user based on the provided email address.</item>
        /// <item>Verifies the provided password against the stored hash.</item>
        /// <item>Fetches the user's roles and claims.</item>
        /// <item>Generates and returns a JWT token using the user's identity information.</item>
        /// </list>
        /// </remarks>
        public async Task<TokenDto> LoginAsync(string email, string password)
        {
            ValidateEmail(email);

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty.");
            }

            User? loginUser = await _userManager.FindByEmailAsync(email) ?? throw new InvalidCredentialException(string.Format(ResponseMessage.InvalidCredentialException, nameof(email)));

            bool isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

            if (!isPasswordMatched)
            {
                throw new InvalidCredentialException(string.Format(ResponseMessage.InvalidCredentialException, nameof(password)));
            }

            return await tokenService.CreateAsync(loginUser);
        }

        /// <summary>
        /// Authenticates a user with the provided email and password, requiring that the user's email has been confirmed.
        /// </summary>
        /// <param name="email">The email address of the user attempting to log in.</param>
        /// <param name="password">The password associated with the provided email address.</param>
        /// <returns>
        /// A <see cref="TokenDto"/> containing the access token and related authentication information.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when the password is null or empty.
        /// </exception>
        /// <exception cref="InvalidCredentialException">
        /// Thrown when the email is invalid, the user does not exist, the password is incorrect, or the email has not been confirmed.
        /// </exception>
        /// <remarks>
        /// This method performs the following operations:
        /// <list type="bullet">
        /// <item>Validates the email format.</item>
        /// <item>Ensures the password is not null or empty.</item>
        /// <item>Retrieves the user based on the provided email.</item>
        /// <item>Checks whether the user's email is confirmed.</item>
        /// <item>Verifies the provided password against the stored password hash.</item>
        /// <item>Retrieves the user's roles and claims.</item>
        /// <item>Generates and returns a JWT token if all checks pass.</item>
        /// </list>
        /// </remarks>
        public async Task<TokenDto> LoginRequireEmailConfirmAsync(string email, string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException(string.Format(ResponseMessage.EmptyOrNullException, nameof(password)));
            }

            ValidateEmail(email);

            User? loginUser = await _userManager.FindByEmailAsync(email) ?? throw new InvalidCredentialException(string.Format(ResponseMessage.InvalidCredentialException, nameof(email)));

            bool isEmailConfirmed = loginUser.EmailConfirmed;

            if (!isEmailConfirmed)
            {
                throw new InvalidCredentialException(string.Format(ResponseMessage.EmailNotValidated, loginUser.Email));
            }

            bool isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

            if (!isPasswordMatched)
            {
                throw new InvalidCredentialException(string.Format(ResponseMessage.InvalidCredentialException, nameof(password)));
            }

            return await tokenService.CreateAsync(loginUser);
        }

        /// <summary>
        /// Authenticates a user using their email and password, then sends a two-factor authentication (2FA) code to the user's email.
        /// </summary>
        /// <param name="email">The email address of the user attempting to log in.</param>
        /// <param name="password">The password associated with the provided email address.</param>
        /// <returns>
        /// A boolean value indicating whether the 2FA code was successfully sent to the user's email.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when the password is null or empty.
        /// </exception>
        /// <exception cref="InvalidCredentialException">
        /// Thrown when the user does not exist or the provided credentials are invalid.
        /// </exception>
        /// <exception cref="UnhandledException">
        /// Thrown when the system fails to generate a two-factor authentication token.
        /// </exception>
        /// <remarks>
        /// This method performs the following operations:
        /// <list type="bullet">
        /// <item>Validates the email format.</item>
        /// <item>Ensures the password is not null or empty.</item>
        /// <item>Retrieves the user by email and checks the password.</item>
        /// <item>Generates a two-factor authentication token.</item>
        /// <item>Sends the generated token to the user's email address.</item>
        /// </list>
        /// </remarks>
        public async Task<bool> LoginWith2FaAsync(string email, string password)
        {
            ValidateEmail(email);

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException(string.Format(ResponseMessage.InvalidCredentialException, nameof(password)));
            }

            User? loginUser = await _userManager.FindByEmailAsync(email) ?? throw new InvalidCredentialException(string.Format(ResponseMessage.InvalidCredentialException, nameof(email)));

            bool isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

            if (!isPasswordMatched)
            {
                throw new InvalidCredentialException(string.Format(ResponseMessage.InvalidCredentialException, nameof(password)));
            }

            string token = await _userManager.GenerateTwoFactorTokenAsync(loginUser, TokenOptions.DefaultProvider);

            if (string.IsNullOrEmpty(token))
            {
                throw new UnhandledException($"Cannot create token, please try again!");
            }

            return EmailHelper.SendEmailTwoFactorCode(loginUser.Email!, token);
        }

        public Task<TokenDto> GoogleLogin(ExternalAuthDto externalAuth)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Assignes a specific claim to a user if the claim value is valid.
        /// </summary>
        /// <param name="userId">The user ID of the user to whom the claim will be added.</param>
        /// <param name="email">The email of the user to whom the claim will be added.</param>
        /// <returns><c>true</c> if the claim is successfully added; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when the user does not exist.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the claim value is not part of the user's valid claims.
        /// </exception>
        /// <remarks>
        /// This method checks if the claim value is already defined for the user. If valid, it adds the claim using ASP.NET Identity's claim system.
        /// </remarks>
        public async Task<bool> AssignClaimsAsync(Guid userId, string email, IList<ClaimDto> claims)
        {
            User? user = (await _userManager.FindByIdAsync(userId.ToString()) ?? await _userManager.FindByEmailAsync(email))
                       ?? throw new ArgumentException($"User with {email} doesn't exists.");

            IEnumerable<Claim>? claimsToAdd = claims?.Select(c => new Claim(c.Type, c.Value));
            IdentityResult addClaimsResult = new IdentityResult();

            if (claimsToAdd != null && claimsToAdd.Any())
            {
                addClaimsResult = await _userManager.AddClaimsAsync(user, claimsToAdd);
            }

            if (!addClaimsResult.Succeeded)
            {
                throw new InvalidDataException("Add claims failed.");
            }

            return addClaimsResult.Succeeded;
        }

        /// <summary>
        /// Adds the specified user to the provided list of roles.
        /// </summary>
        /// <param name="userId">The ID of the user to assign roles to.</param>
        /// <param name="roles">The list of roles to assign to the user.</param>
        /// <returns><c>true</c> if the roles are successfully added; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when the user cannot be found by ID.
        /// </exception>
        /// <remarks>
        /// Validates the list of roles before attempting to assign them to the user. Uses ASP.NET Identity role management.
        /// </remarks>
        public async Task<bool> AssignRolesAsync(Guid userId, IList<string> roles)
        {
            User? user = await _userManager.FindByIdAsync(userId.ToString()) ?? throw new ArgumentException($"User with {userId} doesn't exists.");

            await ValidateRolesAsync(roles);

            IdentityResult identityResult = await _userManager.AddToRolesAsync(user, roles);

            return identityResult.Succeeded;
        }

        /// <summary>
        /// Removes the specified user found by <paramref name="userId"/> from the named roles.
        /// </summary>
        /// <param name="userId">The user found by ID to remove from the named roles.</param>
        /// <param name="roles">The name of the roles to remove the user from.</param>
        /// <returns><c>true</c> if the roles are successfully removed; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when the user cannot be found by ID.
        /// </exception>
        public async Task<bool> UnAssignRolesAsync(Guid userId, IList<string> roles)
        {
            User? user = await _userManager.FindByIdAsync(userId.ToString()) ?? throw new ArgumentException($"User with {userId} doesn't exists.");

            await ValidateRolesAsync(roles);

            IdentityResult identityResult = await _userManager.RemoveFromRolesAsync(user, roles);

            return identityResult.Succeeded;
        }

        /// <summary>
        /// Initializes a new <see cref="User"/> object based on the registration data, validates the input,
        /// creates the user in the identity system, and prepares the associated roles and claims for assignment.
        /// </summary>
        /// <param name="registerModel">The registration model containing user details, password, roles, and claims.</param>
        /// <returns>
        /// A tuple containing the created <see cref="User"/>, a list of assigned role names, and a list of claim DTOs.
        /// </returns>
        /// <exception cref="ValidationException">
        /// Thrown if the user model, roles, or claims are invalid.
        /// </exception>
        /// <exception cref="UnhandledException">
        /// Thrown if the user creation fails with no error information.
        /// </exception>
        /// <remarks>
        /// - Validates the user model and password.
        /// - Ensures provided roles and claims are valid.
        /// - Attempts to create the user using the Identity system.
        /// - If creation fails without clear reason, throws an unhandled exception.
        /// - Sets auditing fields such as CreatedBy, ModifiedBy, and timestamps.
        /// </remarks>
        private async Task<User> InitializeUser(RegisterDto registerModel)
        {
            User newUser = _mapper.Map<User>(registerModel);

            await ValidateModelAsync(newUser, registerModel.Password);

            newUser.CreatedBy = LoginSession.Email ?? registerModel.UserName;
            newUser.ModifiedBy = LoginSession.Email ?? registerModel.UserName;

            newUser.CreatedDate = DateTime.UtcNow;
            newUser.ModifiedDate = DateTime.UtcNow;
            newUser.TenantId = TenantId;

            IdentityResult? identityResult = await _userManager.CreateAsync(newUser, registerModel.Password);

            if (identityResult == null || !identityResult.Succeeded)
            {
                string errorDescriptions = identityResult?.Errors != null
                    ? string.Join("; ", identityResult.Errors.Select(e => $"Code: {e.Code}, Description: {e.Description}"))
                    : "No error details provided.";

                logger.LogError("Failed to create user. Errors: {Errors}", errorDescriptions);

                throw new UnhandledException(ResponseMessage.UnknownError);
            }

            return newUser;
        }

        private async Task AssignDefaultRoles(User user)
        {
            await _userManager.AddToRolesAsync(user, [DefaultRoleName]);
        }
    }
}