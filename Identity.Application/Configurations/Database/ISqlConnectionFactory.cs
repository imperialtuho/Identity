using Identity.Domain.Enums;
using System.Data;

namespace Identity.Application.Configurations.Database
{
    public interface ISqlConnectionFactory
    {
        IDbConnection GetOpenConnection();

        IDbConnection GetNewConnection();

        void SetConnectionStringType(ConnectionStringType connectionStringType);

        (string? connectionString, ConnectionStringType dbType) GetConnectionStringAndDbType();
    }
}