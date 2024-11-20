using Microsoft.AspNetCore.Identity;

namespace Identity.Domain.Entities
{
    public class UserRole : IdentityUserRole<Guid>
    {
        // Navigation properties
        public virtual User User { get; set; }

        public virtual Role Role { get; set; }
    }
}