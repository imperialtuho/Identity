using Identity.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Identity.Infrastructure.Configurations
{
    public class RoleMenuConfiguration : IEntityTypeConfiguration<RoleMenu>
    {
        public void Configure(EntityTypeBuilder<RoleMenu> builder)
        {
            builder.HasKey(rm => new { rm.RoleId, rm.MenuId }); // Composite key

            builder.HasOne(rm => rm.Role)
                   .WithMany(r => r.RoleMenus)
                   .HasForeignKey(rm => rm.RoleId);

            builder.HasOne(rm => rm.Menu)
                   .WithMany(m => m.RoleMenus)
                   .HasForeignKey(rm => rm.MenuId);
        }
    }
}