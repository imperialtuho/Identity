using Identity.Domain.Entities;

namespace Identity.Application.Interfaces.Repositories
{
    public interface IPermissionRepository : IEntityFrameworkGenericRepository<Permission>
    {
        Task<IList<Permission>> GetByRoleIdAsync(Guid roleId);
    }
}