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
                    await roleManager.CreateAsync(new Role(Guid.NewGuid().ToString(), SuperAdmin));
                }

                if (!await roleManager.RoleExistsAsync(Admin))
                {
                    await roleManager.CreateAsync(new Role(Guid.NewGuid().ToString(), Admin));
                }

                if (!await roleManager.RoleExistsAsync(ApiUser))
                {
                    await roleManager.CreateAsync(new Role(Guid.NewGuid().ToString(), ApiUser));
                }

                if (!await roleManager.RoleExistsAsync(DefaultRoleValue.User))
                {
                    await roleManager.CreateAsync(new Role(Guid.NewGuid().ToString(), DefaultRoleValue.User));
                }

                // Users
                var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<User>>();
                string adminUserEmail = "imperialtuho0410@gmail.com";
                string userName = "admin-tuho";
                string password = "imperialtuhoAdmin@0410";

                User? adminUser = await userManager.FindByEmailAsync(adminUserEmail);

                if (adminUser == null)
                {
                    var newSuperAdmin = new User()
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserName = userName,
                        Email = adminUserEmail,
                        EmailConfirmed = true,
                        CreatedBy = SuperAdmin,
                        ModifiedBy = SuperAdmin,
                        CreatedDate = DateTime.UtcNow,
                        ModifiedDate = DateTime.UtcNow
                    };

                    var newClaims = new List<Claim>()
                    {
                        new(type:"Policy", value:Policy.All),
                        new(type:"Policy", value:Policy.Create),
                        new(type:"Policy", value:Policy.Read),
                        new(type:"Policy", value:Policy.Update),
                        new(type:"Policy", value:Policy.Delete),
                    };

                    await userManager.CreateAsync(newSuperAdmin, password);
                    await userManager.AddToRoleAsync(newSuperAdmin, SuperAdmin);
                    await userManager.AddClaimsAsync(newSuperAdmin, newClaims);
                }
            }
        }
    }
}