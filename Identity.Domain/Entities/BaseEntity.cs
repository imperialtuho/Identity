using System.ComponentModel.DataAnnotations;

namespace Identity.Domain.Entities
{
    public class BaseEntity<TId>
    {
        [Key]
        public TId Id { get; set; }

        public int? TenantId { get; set; }

        public DateTime? CreatedDate { get; set; }

        public string? CreatedBy { get; set; }

        public DateTime? ModifiedDate { get; set; } = null!;

        public string? ModifiedBy { get; set; } = null!;

        public bool IsActive { get; set; }

        public bool IsDeleted { get; set; }
    }
}