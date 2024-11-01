using Identity.Domain.Entities;
using Identity.Infrastructure.Database;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Identity.Api.Helpers
{
    public static class DatabaseHelper
    {
        public static async Task SeedAsync(IApplicationBuilder applicationBuilder)
        {
            using (IServiceScope serviceScope = applicationBuilder.ApplicationServices.CreateScope())
            {
                var context = serviceScope.ServiceProvider.GetService<ApplicationDbContext>();

                await context!.Database.EnsureCreatedAsync();
            }

            using (IServiceScope serviceScope = applicationBuilder.ApplicationServices.CreateScope())
            {
                // Roles
                var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<Role>>();

                if (!await roleManager.RoleExistsAsync(SuperAdmin))
                {
                    await roleManager.CreateAsync(new Role(Guid.NewGuid(), SuperAdmin));
                }

                if (!await roleManager.RoleExistsAsync(Admin))
                {
                    await roleManager.CreateAsync(new Role(Guid.NewGuid(), Admin));
                }

                if (!await roleManager.RoleExistsAsync(ApiUser))
                {
                    await roleManager.CreateAsync(new Role(Guid.NewGuid(), ApiUser));
                }

                if (!await roleManager.RoleExistsAsync(DefaultRoleValue.User))
                {
                    await roleManager.CreateAsync(new Role(Guid.NewGuid(), DefaultRoleValue.User));
                }

                // Users
                var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<User>>();

                IList<User> users = [
                new()
                {
                    UserName = "admin-tuho",
                    Email = "imperialtuho0410@gmail.com",
                    DisplayName = "Imperial Tu Ho",
                    FirstName = "Tu",
                    LastName = "Ho",
                    Bio = "Russian Bias",
                    EmailConfirmed = true,
                    CreatedBy = SuperAdmin,
                    ModifiedBy = null,
                    CreatedDate = DateTime.UtcNow,
                    ModifiedDate = null,
                    TenantId = 1,
                    IsAdmin = true,
                },
                new()
                {
                    UserName = "ApiUser-Tenant-0",
                    Email = "ApiTenant0@example.com",
                    DisplayName = "ApiUser-Tenant-1",
                    FirstName = "Api",
                    LastName = "User",
                    Bio = null,
                    EmailConfirmed = true,
                    CreatedBy = SuperAdmin,
                    ModifiedBy = null,
                    CreatedDate = DateTime.UtcNow,
                    ModifiedDate = null,
                    TenantId = 1,
                    IsAdmin = false,
                }];

                foreach (User user in users)
                {
                    User? existUser = await userManager.FindByEmailAsync(user.Email!);

                    if (existUser == null)
                    {
                        string defaultPassword = "ApiUserTenant0@0410";
                        var newClaims = new List<Claim>()
                    {
                        new(type:nameof(Policy), value:Policy.All),
                        new(type:nameof(Policy), value:Policy.Create),
                        new(type:nameof(Policy), value:Policy.Read),
                        new(type:nameof(Policy), value:Policy.Update),
                        new(type:nameof(Policy), value:Policy.Delete),
                    };

                        if (user.IsAdmin)
                        {
                            defaultPassword = "imperialtuhoAdmin@0410";
                        }

                        await userManager.CreateAsync(user, defaultPassword);
                        await userManager.AddToRoleAsync(user, user.IsAdmin ? SuperAdmin : ApiUser);
                        await userManager.AddClaimsAsync(user, newClaims);
                    }
                }
            }
        }
    }
}