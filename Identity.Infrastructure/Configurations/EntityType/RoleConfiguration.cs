﻿using Identity.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Identity.Infrastructure.Configurations.EntityType
{
    public class RoleConfiguration : IEntityTypeConfiguration<Role>
    {
        public void Configure(EntityTypeBuilder<Role> builder)
        {
            // Define the table name
            builder.ToTable("Roles");

            // Define the key for the Role
            builder.HasKey(r => r.Id);

            builder.Property(r => r.NormalizedName)
                   .HasMaxLength(256); // Index for normalized role name

            builder.Property(r => r.ConcurrencyStamp)
                   .IsConcurrencyToken(); // Used for optimistic concurrency control

            // Define the relationship between Role and UserRole
            builder.HasMany(r => r.UserRoles) // A Role has many UserRoles
                   .WithOne(ur => ur.Role) // A UserRole has one Role
                   .HasForeignKey(ur => ur.RoleId) // The foreign key in UserRole
                   .OnDelete(DeleteBehavior.Cascade); // Cascade delete UserRoles when Role is deleted

            // Optionally, configure the RolePermissions relationship (if you're using that)
            builder.HasMany(r => r.RolePermissions)  // Role has many RolePermissions
                   .WithOne(rp => rp.Role)   // RolePermission has one Role
                   .HasForeignKey(rp => rp.RoleId)  // Foreign key in RolePermissions
                   .OnDelete(DeleteBehavior.Cascade); // Cascade delete when Role is deleted
        }
    }
}