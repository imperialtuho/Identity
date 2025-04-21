using AutoMapper;
using Identity.Application.Configurations.Settings;
using Identity.Application.Dtos.Users;
using Identity.Domain.Common;
using Identity.Domain.Entities;
using Identity.Domain.Exceptions;
using Identity.Domain.Extensions;
using Identity.Domain.SharedKernel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text.RegularExpressions;

namespace Identity.Application.Services.Base
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserAuthBaseService"/> class with the required dependencies.
    /// </summary>
    /// <param name="userManager">The user manager for managing users.</param>
    /// <param name="roleManager">The role manager for managing roles.</param>
    /// <param name="passwordHasher">The password hasher used to hash and verify passwords.</param>
    /// <param name="applicationSettings">The application-wide configuration settings.</param>
    /// <param name="mapper">The AutoMapper instance for object mapping.</param>
    /// <param name="httpContextAccessor">The HTTP context accessor to retrieve session and tenant information.</param>
    /// <exception cref="ArgumentNullException">Thrown when any required dependency is null.</exception>
    public class UserAuthBaseService(UserManager<User> userManager,
        RoleManager<Role> roleManager,
        IPasswordHasher<User> passwordHasher,
        IOptions<ApplicationSettings> applicationSettings,
        IOptions<JwtSettings> jwtSettings,
        IMapper mapper,
        IHttpContextAccessor httpContextAccessor)
    {
        protected readonly ApplicationSettings _applicationSettings = applicationSettings.Value;
        protected readonly JwtSettings _jwtSettings = jwtSettings.Value;
        protected readonly IMapper _mapper = mapper;
        protected readonly IPasswordHasher<User> _passwordHasher = passwordHasher;
        protected readonly UserManager<User> _userManager = userManager;
        protected readonly RoleManager<Role> _roleManager = roleManager;
        protected readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

        // Default Values
        protected int TenantId => _applicationSettings.TenantId;

        protected double DefaultExpiryInDays => double.Parse(_jwtSettings.RefreshTokenValidityInDays);
        protected double TokenValidityInSeconds => double.Parse(_jwtSettings.TokenValidityInSeconds);
        protected const string SecurityAlgorithmMethod = SecurityAlgorithms.HmacSha256Signature;
        protected const string DefaultRoleName = ApplicationDefaultRoleValue.AppUser;

        /// <summary>
        /// Retrieves the current user session associated with the active HTTP request.
        /// </summary>
        /// <value>
        /// Returns an instance of <see cref="UserSession"/> containing information about the authenticated user.
        /// </value>
        /// <remarks>
        /// This property provides access to user-specific session data extracted from the HTTP context,
        /// typically used for authentication, authorization, or auditing purposes.
        /// </remarks>
        protected UserSession LoginSession => _httpContextAccessor.GetUserSession();

        protected readonly string EmailPattern = @"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$";
        protected readonly string PasswordPattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$";
        private const int NameMinLengthLimit = 1;

        /// <summary>
        /// Validates the specified list of claims to ensure that each claim has a non-empty <c>Type</c> and <c>Value</c>.
        /// </summary>
        /// <param name="claims">The list of <see cref="ClaimDto"/> objects to validate.</param>
        /// <exception cref="ArgumentException">
        /// Thrown when one or more claims have a null or empty <c>Type</c> or <c>Value</c>.
        /// </exception>
        /// <remarks>
        /// This method is typically used during user creation or role assignment to ensure claim integrity.
        /// Each claim must contain both a valid type and value to be considered valid.
        /// </remarks>
        protected static void ValidateClaims(IList<ClaimDto>? claims)
        {
            if (claims != null && claims.Any(c => string.IsNullOrEmpty(c.Type) || string.IsNullOrEmpty(c.Value)))
            {
                throw new ArgumentException($"Claim type and value must not be empty.");
            }
        }

        /// <summary>
        /// Validates the specified email address against the configured pattern.
        /// </summary>
        /// <param name="email">The email address to validate.</param>
        /// <exception cref="ArgumentException">
        /// Thrown when the email is null, empty, or does not match the expected pattern.
        /// </exception>
        /// <remarks>
        /// This method ensures that the provided email address is both present and matches the standard format defined by <see cref="EmailPattern"/>.
        /// It is typically called before creating or updating user records to enforce email format consistency.
        /// </remarks>
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

        /// <summary>
        /// Validates the specified password against the configured complexity requirements.
        /// </summary>
        /// <param name="password">The password to validate.</param>
        /// <exception cref="ArgumentException">
        /// Thrown when the password is null, empty, or does not meet the required complexity criteria.
        /// </exception>
        /// /// <remarks>
        /// This method checks that the password:
        /// <list type="bullet">
        /// <item><description>Has at least 8 characters</description></item>
        /// <item><description>Contains at least 1 uppercase letter</description></item>
        /// <item><description>Contains at least 1 lowercase letter</description></item>
        /// <item><description>Contains at least 1 digit</description></item>
        /// <item><description>Contains at least 1 special character (e.g., #?!@$%&#94;&amp;*-)</description></item>
        /// </list>
        /// </remarks>
        protected void ValidatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is required.");
            }

            string passwordPattern = PasswordPattern;

            if (!Regex.IsMatch(password, passwordPattern))
            {
                throw new ArgumentException(@"Password must have at least 8 characters, at least 1 uppercase letter, at least 1 lowercase letter, at least 1 digit and at least 1 special character.");
            }
        }

        /// <summary>
        /// Validates the provided list of role names against the roles defined in the system.
        /// </summary>
        /// <param name="roles">The list of role names to validate.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when one or more of the provided roles do not exist in the system.
        /// </exception>
        /// <remarks>
        /// This method checks that all specified roles exist within the role store managed by <see cref="RoleManager{Role}"/>.
        /// If the <paramref name="roles"/> list is null or empty, validation is skipped.
        /// </remarks>
        protected async Task ValidateRolesAsync(IList<string>? roles)
        {
            if (roles == null || !roles.Any()) return;  // No roles to validate, so exit early

            // Fetch valid roles from the system
            List<string?>? validRoles = await _roleManager.Roles.Select(r => r.Name).ToListAsync();

            // Check for any roles that are not valid system roles
            bool invalidRoles = roles.Except(validRoles).Any();

            if (invalidRoles)
            {
                throw new ArgumentException($"The following roles are invalid: {string.Join(", ", invalidRoles)}.");
            }
        }

        /// <summary>
        /// Validates the provided username for null, empty, or insufficient length.
        /// </summary>
        /// <param name="name">The username to validate.</param>
        /// <exception cref="ArgumentException">
        /// Thrown when the <paramref name="name"/> is null, empty, or shorter than the required minimum length.
        /// </exception>
        /// <remarks>
        /// This method ensures the username is not null or empty, and meets the minimum character length defined by <c>NameLength</c>.
        /// </remarks>
        protected static void ValidateUserName(string? name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"{nameof(name)} is required.");
            }

            if (name.Length < NameMinLengthLimit)
            {
                throw new ArgumentException($"{nameof(name)} must have at least {NameMinLengthLimit} characters.");
            }
        }

        /// <summary>
        /// Validates the user model for uniqueness and correctness of email, username, password, and display name.
        /// </summary>
        /// <param name="requestModel">The <see cref="User"/> model to validate.</param>
        /// <param name="password">The password to validate. This is only required for new user creation.</param>
        /// <param name="isUpdate">
        /// A boolean flag indicating whether the operation is an update.
        /// If <c>true</c>, password validation is skipped.
        /// </param>
        /// <returns>A <see cref="Task"/> representing the asynchronous validation operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="requestModel"/> is null.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if the email, username, or display name already exists and belongs to another user.
        /// </exception>
        /// <remarks>
        /// This method performs the following validations:
        /// - Ensures the provided email and username are valid formats.
        /// - Validates the password if not in update mode.
        /// - Ensures the email and username are unique across all users, except the one being updated (if applicable).
        /// - Ensures the display name is unique among all users.
        /// </remarks>
        protected async Task ValidateModelAsync(User requestModel, string password, bool isUpdate = false)
        {
            ArgumentNullException.ThrowIfNull(requestModel);

            ValidateEmail(requestModel.Email);
            ValidateUserName(requestModel.UserName);

            if (!isUpdate)
            {
                ValidatePassword(password);
            }

            User? foundUserByEmail = await _userManager.FindByEmailAsync(requestModel.Email!);
            User? foundUserByUserName = await _userManager.FindByNameAsync(requestModel.UserName!);

            bool isDisplayNameTaken = await _userManager.Users.AnyAsync(u => u.DisplayName.Equals(requestModel.DisplayName));

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

        /// <summary>
        /// Determines whether the action is performed by an admin user.
        /// </summary>
        /// <param name="currentUser">The current user session. If null, assumes a non-admin user.</param>
        /// <param name="tenantId">Optional tenant ID to check admin scope.</param>
        /// <returns>True if the user is a SuperAdmin or an Admin in the specified tenant; otherwise, false.</returns>
        /// <remarks>
        /// A user is considered an admin if they have the 'SuperAdmin' role, or the 'Admin' role within the same tenant.
        /// </remarks>
        protected static bool IsActionPerformedByAdmin(UserSession? currentUser = null, int? tenantId = null)
        {
            if (currentUser is null || currentUser.Roles is null)
                return false;

            // Check SuperAdmin role
            if (currentUser.Roles.Any(r => r == ApplicationDefaultRoleValue.SuperAdmin))
                return true;

            // Check Admin role with matching tenant
            if (currentUser.Roles.Any(r => r == ApplicationDefaultRoleValue.Admin) && currentUser.TenantId == tenantId)
                return true;

            return false;
        }

        /// <summary>
        /// Validates whether the current user is authorized to perform an operation based on role or ownership.
        /// </summary>
        /// <param name="ownerId">The ID of the resource owner.</param>
        /// <param name="tenantId">The tenant ID to validate against for tenant-scoped admin access.</param>
        /// <exception cref="ForbiddenException">Thrown when the user is unauthorized to perform the operation.</exception>
        /// <remarks>
        /// An action is allowed if the user is a SuperAdmin, an Admin within the same tenant, or the resource owner.
        /// </remarks>
        protected void CheckingCurrentPerformingOperation(Guid? ownerId = null, int? tenantId = null)
        {
            UserSession? loginSession = LoginSession ?? throw new ForbiddenException();

            // Admin check
            if (IsActionPerformedByAdmin(loginSession, tenantId)) return;

            // Ownership check
            if (ownerId is not null && loginSession.UserId == ownerId && loginSession.TenantId == tenantId) return;

            throw new ForbiddenException();
        }
    }
}