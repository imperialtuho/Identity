using Identity.Domain.Entities;

namespace Identity.Application.Interfaces.Repositories
{
    public interface IMenuRepository : IEFGenericRepository<Menu>
    {
        Task<Menu> GetByIdAsync(string id, bool includeDeleted);

        Task<List<Menu>> GetAllAsync(string userId);

        Task<bool> DeleteAsync(string id, string author);

        //Task<bool> UpdateListAsync(List<UpdateMenuListRequest> menus);

        Task<bool> CreateAsync(Menu menu);

        Task<bool> UpdateAsync(Menu request);
    }
}