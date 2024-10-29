using Identity.Application.Configurations.Database;
using Identity.Domain.Entities;
using Identity.Domain.Enums;
using Identity.Infrastructure.Repositories.Providers;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

namespace Identity.Infrastructure.Configurations
{
    public abstract class DbSqlConnectionEFRepositoryBase<C, T> : EntityFrameworkGenericRepository<C, T>
        where T : BaseEntity<Guid>
        where C : DbContext, new()
    {
        protected DbSqlConnectionEFRepositoryBase(ISqlConnectionFactory sqlConnectionFactory, IHttpContextAccessor httpContextAccessor)
            : base(CreateDbContextOptions(sqlConnectionFactory, ConnectionStringType.SqlServerConnection), sqlConnectionFactory, httpContextAccessor)
        {
        }
    }
}