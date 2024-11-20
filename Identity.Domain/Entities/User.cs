using Identity.Domain.Common;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Identity.Domain.Entities
{
    public class User : IdentityUser<Guid>
    {
        public string FirstName { get; set; }

        public string LastName { get; set; }

        public string DisplayName { get; set; }

        [StringLength(500)]
        public string? Bio { get; set; }

        [Url]
        public string? ProfilePictureUrl { get; set; }

        public string Title { get; set; } = AccountTitle.NewBie;

        public string? CellPhone { get; set; }

        public string? SecondaryCellPhone { get; set; }

        public DateTime? CreatedDate { get; set; }

        public string? CreatedBy { get; set; }

        public DateTime? ModifiedDate { get; set; }

        public string? ModifiedBy { get; set; }

        public bool IsDeleted { get; set; }

        public int? TenantId { get; set; }

        public bool IsAdmin { get; set; }

        public virtual ICollection<RefreshToken> RefreshTokens { get; set; }

        public virtual ICollection<UserMenu> UserMenus { get; set; }

        public ICollection<UserRole> UserRoles { get; set; }
    }
}