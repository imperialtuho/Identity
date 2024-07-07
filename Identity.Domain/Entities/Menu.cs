using System.ComponentModel.DataAnnotations;

namespace Identity.Domain.Entities
{
    public class Menu : BaseEntity<string>
    {
        public Menu()
        {
            Children = new HashSet<Menu>();
        }

        [Required]
        [StringLength(50)]
        public string Title { get; set; }

        [StringLength(100)]
        public string Description { get; set; }

        [StringLength(50)]
        public string Icon { get; set; }

        [StringLength(50)]
        public string Url { get; set; }

        public string? ParentId { get; set; } = null;

        public int? OrderNumber { get; set; }

        public virtual ICollection<Menu> Children { get; set; }

        public virtual Menu ParentItem { get; set; }

        public virtual ICollection<RoleMenu> RoleMenus { get; set; }

        public virtual ICollection<UserMenu> UserMenus { get; set; }
    }
}