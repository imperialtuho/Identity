using Microsoft.AspNetCore.Identity;

namespace Identity.Domain.Entities
{
    public class Role : IdentityRole<Guid>
    {
        public Role()
        { }

        public Role(Guid id, string name) : this()
        {
            Id = id;
            Name = name;
        }

        public virtual ICollection<RoleMenu> RoleMenus { get; set; }
        public string Description { get; set; }
        public ICollection<RolePermission> RolePermissions { get; set; }
        public ICollection<UserRole> UserRoles { get; set; }
    }
}