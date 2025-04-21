using Identity.Domain.Enums;

namespace Identity.Domain.Entities
{
    public class UserDeleteRequest : BaseEntity<Guid>
    {
        public Guid UserId { get; set; }

        public string Reason { get; set; }

        public string Status { get; set; } = nameof(DeleteRequestStatus.New);
    }
}