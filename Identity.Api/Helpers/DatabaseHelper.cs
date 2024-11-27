using Identity.Domain.Entities;
using Identity.Infrastructure.Database;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Identity.Api.Helpers
{
    public static class DatabaseHelper
    {
        public static async Task SeedAsync(IApplicationBuilder applicationBuilder)
        {
            using IServiceScope serviceScope = applicationBuilder.ApplicationServices.CreateScope();

            // DbContext
            var dbContext = serviceScope.ServiceProvider.GetService<ApplicationDbContext>();
            // Roles
            var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<Role>>();
            // Users
            var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<User>>();

            await dbContext!.Database.EnsureCreatedAsync();

            // Step 1: Seed Permissions
            var permissions = new List<Permission>
            {
                new () { Id = Guid.NewGuid(), Name = ApplicationPolicies.Super, Description = "All permission" },
                new () { Id = Guid.NewGuid(), Name = ApplicationPolicies.Create, Description = "Create permission" },
                new () { Id = Guid.NewGuid(), Name = ApplicationPolicies.Read, Description = "Read permission" },
                new () { Id = Guid.NewGuid(), Name = ApplicationPolicies.Update, Description = "Update permission" },
                new () { Id = Guid.NewGuid(), Name = ApplicationPolicies.Delete, Description = "Delete permission" }
            };

            foreach (Permission permission in permissions)
            {
                if (!(await dbContext.Permissions.AnyAsync(p => p.Name == permission.Name)))
                {
                    dbContext.Permissions.Add(permission);
                }
            }

            await dbContext.SaveChangesAsync();

            // Step 2: Seed Roles and Assign Permissions
            async Task CreateRoleWithPermissionsAsync(string roleName, IEnumerable<string> permissionNames)
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    var role = new Role { Id = Guid.NewGuid(), Name = roleName };
                    await roleManager.CreateAsync(role);

                    var rolePermissions = permissionNames.Select(permissionName => new RolePermission
                    {
                        RoleId = role.Id,
                        PermissionId = dbContext.Permissions.Single(p => p.Name == permissionName).Id
                    });

                    await dbContext.RolePermissions.AddRangeAsync(rolePermissions);
                    await dbContext.SaveChangesAsync();
                }
            }

            // Define roles with associated permissions
            await CreateRoleWithPermissionsAsync(SuperAdmin, permissions.Select(p => p.Name));
            await CreateRoleWithPermissionsAsync(Admin, [ApplicationPolicies.Read, ApplicationPolicies.Create, ApplicationPolicies.Update, ApplicationPolicies.Delete]);
            await CreateRoleWithPermissionsAsync(ApiUser, [ApplicationPolicies.Read, ApplicationPolicies.Create, ApplicationPolicies.Update]);
            await CreateRoleWithPermissionsAsync(AppUser, [ApplicationPolicies.Read, ApplicationPolicies.Create, ApplicationPolicies.Update]);

            IList<User> users = [
            new()
                {
                    UserName = "admin-tuho",
                    Email = "imperialtuho0410@gmail.com",
                    DisplayName = "Imperial Tu Ho",
                    FirstName = "Tu",
                    LastName = "Ho",
                    Bio = "Russian Bias",
                    Title = "Manager",
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
                    Title = "Api",
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
                User? existingUser = await userManager.FindByEmailAsync(user.Email!);

                if (existingUser == null)
                {
                    string? defaultPassword = user.IsAdmin ? "imperialtuhoAdmin@0410" : "ApiUserTenant0@0410";

                    await userManager.CreateAsync(user, defaultPassword);

                    string? roleName = user.IsAdmin ? SuperAdmin : ApiUser;

                    await userManager.AddToRoleAsync(user, roleName);

                    // Add claims based on permissions of assigned role
                    Role? role = await roleManager.FindByNameAsync(roleName) ?? new();

                    // Fetch the role permissions and execute the query immediately
                    IList<string> rolePermissions = await dbContext.RolePermissions
                        .Where(rp => rp.RoleId == role.Id)
                        .Select(rp => rp.Permission.Name)
                        .ToListAsync();  // Executes and fetches the result

                    foreach (string permission in rolePermissions)
                    {
                        await userManager.AddClaimAsync(user, new Claim("Permission", permission));
                    }
                }
            }
        }
    }
}