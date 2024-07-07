using Microsoft.AspNetCore.Identity;

namespace Identity.Domain.Entities
{
    public class Role : IdentityRole<string>
    {
        public Role()
        { }

        public Role(string id, string name) : this()
        {
            Id = id;
            Name = name;
        }

        public virtual ICollection<RoleMenu> RoleMenus { get; set; }
    }
}