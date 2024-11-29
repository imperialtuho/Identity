namespace Identity.Application.Dtos.Base
{
    public class BaseDto
    {
        public int? TenantId { get; set; }

        public DateTime? CreatedDate { get; set; }

        public string? CreatedBy { get; set; }

        public DateTime? ModifiedDate { get; set; }

        public string? ModifiedBy { get; set; }

        public bool IsActive { get; set; }
    }
}