using Microsoft.AspNetCore.Identity;

namespace Identity.Domain.Entities
{
    public class UserRole : IdentityUserRole<Guid>
    {
        public virtual User User { get; set; }       // Navigation property to User
        public virtual Role Role { get; set; }       // Navigation property to Role
    }
}