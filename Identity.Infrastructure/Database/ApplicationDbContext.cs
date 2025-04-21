using Identity.Domain.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Reflection;

namespace Identity.Infrastructure.Database
{
    /// <summary>
    /// Represents the application database context, inheriting from <see cref="IdentityDbContext{User, Role, Guid}"/>.
    /// </summary>
    /// <remarks>
    /// This class provides access to the application’s data models and is responsible for configuring the
    /// Entity Framework Core database context. It also includes the mappings between the application's
    /// entities (e.g., <see cref="User"/>, <see cref="Role"/>, <see cref="RefreshToken"/>, etc.) and the
    /// corresponding database tables. This context also handles configuration for global query filters
    /// (e.g., soft deletes) and entity relationships.
    /// </remarks>
    public class ApplicationDbContext : IdentityDbContext<User, Role, Guid>
    {
        /// <summary>
        /// Gets or sets the database table for <see cref="RefreshToken"/>.
        /// </summary>
        /// <remarks>
        /// This property represents the table corresponding to <see cref="RefreshToken"/> in the database.
        /// The <see cref="DbSet{RefreshToken}"/> provides access to all CRUD operations for the RefreshToken entity.
        /// </remarks>
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        /// <summary>
        /// Gets or sets the database table for <see cref="Permission"/>.
        /// </summary>
        /// <remarks>
        /// This property represents the table corresponding to <see cref="Permission"/> in the database.
        /// The <see cref="DbSet{Permission}"/> provides access to all CRUD operations for the Permission entity.
        /// </remarks>
        public DbSet<Permission> Permissions { get; set; }

        /// <summary>
        /// Gets or sets the database table for <see cref="RolePermission"/>.
        /// </summary>
        /// <remarks>
        /// This property represents the table corresponding to <see cref="RolePermission"/> in the database.
        /// The <see cref="DbSet{RolePermission}"/> provides access to all CRUD operations for the RolePermission entity.
        /// </remarks>
        public DbSet<RolePermission> RolePermissions { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ApplicationDbContext"/> class.
        /// </summary>
        public ApplicationDbContext()
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ApplicationDbContext"/> class with the specified options.
        /// </summary>
        /// <param name="options">The options to be used by the <see cref="DbContext"/>.</param>
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        { }

        /// <summary>
        /// Configures the model for the database context.
        /// </summary>
        /// <param name="builder">The model builder used to configure the entity mappings.</param>
        /// <remarks>
        /// This method configures the entity model for the application, including applying configurations from
        /// the assembly and setting up query filters (e.g., ensuring that soft-deleted users are excluded by default).
        /// </remarks>
        protected override void OnModelCreating(ModelBuilder builder)
        {
            // Apply configurations from the current assembly
            builder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());

            // Call the base class method for IdentityDbContext configuration
            base.OnModelCreating(builder);
        }
    }
}