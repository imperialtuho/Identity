using Identity.Application.Configurations.Database;
using Identity.Application.Configurations.Settings;
using Identity.Application.Interfaces.Repositories;
using Identity.Domain.Common;
using Identity.Domain.Entities;
using Identity.Infrastructure.Configurations;
using Identity.Infrastructure.Database;
using Identity.Infrastructure.Repositories.Providers.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Identity.Infrastructure
{
    public static class DependencyInjection
    {
        /// <summary>
        /// Adds Infrastructure Services.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <param name="configuration">The configuration.</param>
        /// <returns>IServiceCollection.</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"), b => b.MigrationsAssembly("Identity.Api"));
            });

            var jwtSettings = configuration.GetSection(nameof(JwtSettings)).Get<JwtSettings>() ?? throw new InvalidDataException($"{nameof(JwtSettings)} are not setup!");

            services.AddIdentityCore<User>(options =>
            {
                // Password settings.
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 8;

                // Lockout settings.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                options.Lockout.MaxFailedAccessAttempts = 6;
                options.Lockout.AllowedForNewUsers = false;

                // User settings.
                options.User.RequireUniqueEmail = true;
            })
            .AddRoles<Role>()
            .AddClaimsPrincipalFactory<UserClaimsPrincipalFactory<User, Role>>()
            .AddEntityFrameworkStores<ApplicationDbContext>();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.SaveToken = true;
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = true,
                    ValidAudience = jwtSettings.Audience,
                    ValidIssuer = jwtSettings.Issuer,
                    ClockSkew = TimeSpan.Zero,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key))
                };
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Append("Token-Expired", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            // Adds system policies.
            List<string> allowRoles = [ApplicationDefaultRoleValue.SuperAdmin, ApplicationDefaultRoleValue.Admin, ApplicationDefaultRoleValue.AppUser, ApplicationDefaultRoleValue.ApiUser];

            string roles = string.Join(",", allowRoles);
            string claimType = nameof(Permission);

            services.AddAuthorizationBuilder()
                .AddPolicy(nameof(ApplicationPolicies.Create), policy =>
                {
                    policy.RequireClaim(claimType, ApplicationPolicies.Create);
                    policy.RequireRole($"{roles}");
                })
                .AddPolicy(nameof(ApplicationPolicies.Read), policy =>
                {
                    policy.RequireClaim(claimType, ApplicationPolicies.Read);
                    policy.RequireRole($"{roles}");
                })
                .AddPolicy(nameof(ApplicationPolicies.Update), policy =>
                {
                    policy.RequireClaim(claimType, ApplicationPolicies.Update);
                    policy.RequireRole($"{roles}");
                })
                .AddPolicy(nameof(ApplicationPolicies.Delete), policy =>
                {
                    policy.RequireClaim(claimType, ApplicationPolicies.Delete);
                    policy.RequireRole($"{roles}");
                })
                .AddPolicy(nameof(ApplicationPolicies.Super), policy =>
                {
                    policy.RequireClaim(claimType, ApplicationPolicies.Super);
                    policy.RequireRole(ApplicationDefaultRoleValue.SuperAdmin);
                });

            // Adds Repositories.
            services.AddScoped<ISqlConnectionFactory, SqlConnectionFactory>();
            services.AddScoped<ITokenRepository, JwtTokenRepository>();
            services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
            services.AddScoped<IPermissionRepository, PermissionRepository>();

            return services;
        }
    }
}