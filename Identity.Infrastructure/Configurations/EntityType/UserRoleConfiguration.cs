using Identity.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Identity.Infrastructure.Configurations.EntityType
{
    public class UserRoleConfiguration : IEntityTypeConfiguration<UserRole>
    {
        public void Configure(EntityTypeBuilder<UserRole> builder)
        {
            // Configure the relationship between UserRole and User
            builder.HasOne(ur => ur.User) // A UserRole has one User
                   .WithMany(u => u.UserRoles) // A User has many UserRoles
                   .HasForeignKey(ur => ur.UserId) // The foreign key in UserRole
                   .OnDelete(DeleteBehavior.Cascade); // Cascade delete for User, but keep the Role

            // Configure the relationship between UserRole and Role
            builder.HasOne(ur => ur.Role) // A UserRole has one Role
                   .WithMany(r => r.UserRoles) // A Role has many UserRoles
                   .HasForeignKey(ur => ur.RoleId) // The foreign key in UserRole
                   .OnDelete(DeleteBehavior.Cascade); // Cascade delete for Role, but keep the User
        }
    }
}