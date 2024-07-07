using Identity.Domain.Entities;

namespace Identity.Application.Interfaces.Services
{
    public interface IMenuService
    {
        Task<Menu> GetByIdAsync(string id);

        Task<Menu> GetAllByUserIdAsync(string userId);

        //Task<Menu> CreateAsync(CreateMenuRequest request);

        //Task<Menu> UpdateAsync(UpdateMenuRequest request);

        Task<bool> DeleteAsync(string id);

        //Task<bool> UpdateListAsync(List<UpdateMenuListRequest> menus);
    }
}