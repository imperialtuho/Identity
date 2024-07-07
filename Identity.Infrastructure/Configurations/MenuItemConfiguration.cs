using Identity.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Identity.Infrastructure.Configurations
{
    public class MenuItemConfiguration : IEntityTypeConfiguration<Menu>
    {
        public void Configure(EntityTypeBuilder<Menu> builder)
        {
            builder.ToTable("MenuItems");
            builder.HasMany(menuItem => menuItem.Children)
                   .WithOne(menuItem => menuItem.ParentItem)
                   .HasForeignKey(menuItem => menuItem.ParentId);

            // Add RoleMenu configuration
            builder.HasMany(menuItem => menuItem.RoleMenus)
                   .WithOne(roleMenu => roleMenu.Menu)
                   .HasForeignKey(roleMenu => roleMenu.MenuId);

            // Add UserMenu configuration
            builder.HasMany(menuItem => menuItem.UserMenus)
                   .WithOne(userMenu => userMenu.Menu)
                   .HasForeignKey(userMenu => userMenu.MenuId);
        }
    }
}