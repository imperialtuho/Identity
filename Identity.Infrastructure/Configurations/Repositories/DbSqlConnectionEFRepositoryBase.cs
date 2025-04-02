using Identity.Application.Configurations.Database;
using Identity.Domain.Entities;
using Identity.Domain.Enums;
using Identity.Infrastructure.Repositories.Providers;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Identity.Infrastructure.Configurations.Repositories
{
    /// <summary>
    /// A base repository that provides Entity Framework-based database operations
    /// for SQL Server connections, inheriting from the generic <see cref="EntityFrameworkGenericRepository{C, T}"/>.
    /// </summary>
    /// <typeparam name="C">The type of the database context, which must inherit from <see cref="DbContext"/>.</typeparam>
    /// <typeparam name="T">The type of the entity, which must inherit from <see cref="BaseEntity{string}"/>.</typeparam>
    /// <remarks>
    /// This class acts as a base class for repositories that interact with an SQL Server database, using Entity Framework
    /// for data access operations. It provides the necessary setup for managing database connections, performing CRUD operations,
    /// and interacting with the HTTP context, with SQL Server-specific configuration.
    /// </remarks>
    public abstract class DbSqlConnectionEFRepositoryBase<C, T> : EntityFrameworkGenericRepository<C, T>
        where T : BaseEntity<Guid>
        where C : DbContext, new()
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DbSqlConnectionEFRepositoryBase{C, T}"/> class.
        /// </summary>
        /// <param name="sqlConnectionFactory">The SQL connection factory used to configure the database connection.</param>
        /// <param name="httpContextAccessor">The HTTP context accessor that provides access to the HTTP context.</param>
        /// <param name="logger">The logger used for logging purposes within the repository.</param>
        /// <remarks>
        /// The constructor sets up the database context options for SQL Server and invokes the base class constructor.
        /// It also ensures that the repository has access to the necessary SQL connection, HTTP context, and logging mechanism.
        /// </remarks>
        protected DbSqlConnectionEFRepositoryBase(ISqlConnectionFactory sqlConnectionFactory, IHttpContextAccessor httpContextAccessor, ILogger<DbSqlConnectionEFRepositoryBase<C, T>> logger)
            : base(CreateDbContextOptions(sqlConnectionFactory, ConnectionStringType.SqlServerConnection), sqlConnectionFactory, httpContextAccessor, logger)
        {
        }
    }
}