using Identity.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Identity.Infrastructure.Configurations.EntityType
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            // Define the relationship between User and UserRole
            builder.HasMany(u => u.UserRoles) // A User has many UserRoles
                   .WithOne(ur => ur.User) // A UserRole has one User
                   .HasForeignKey(ur => ur.UserId) // The foreign key in UserRole
                   .OnDelete(DeleteBehavior.Cascade); // Cascade delete UserRoles when User is deleted
        }
    }
}