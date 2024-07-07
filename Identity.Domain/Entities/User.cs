using Microsoft.AspNetCore.Identity;

namespace Identity.Domain.Entities
{
    public class User : IdentityUser<string>
    {
        public DateTime? CreatedDate { get; set; }

        public string CreatedBy { get; set; }

        public DateTime? ModifiedDate { get; set; } = null!;

        public string ModifiedBy { get; set; } = null!;

        public bool IsDeleted { get; set; }

        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();

        public virtual ICollection<UserMenu> UserMenus { get; set; }
    }
}