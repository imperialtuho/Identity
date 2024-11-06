using Identity.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Identity.Infrastructure.Configurations.EntityType
{
    public class UserMenuConfiguration : IEntityTypeConfiguration<UserMenu>
    {
        public void Configure(EntityTypeBuilder<UserMenu> builder)
        {
            builder.HasKey(um => new { um.UserId, um.MenuId }); // Composite key

            builder.HasOne(um => um.User)
                   .WithMany(u => u.UserMenus)
                   .HasForeignKey(um => um.UserId);

            builder.HasOne(um => um.Menu)
                   .WithMany(m => m.UserMenus)
                   .HasForeignKey(um => um.MenuId);
        }
    }
}