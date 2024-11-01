namespace Identity.Domain.SharedKernel
{
    public class UserSession
    {
        public Guid UserId { set; get; }

        public List<string>? Roles { get; set; }

        public int? TenantId { get; set; }

        public string? Email { get; set; }
    }
}