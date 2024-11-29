namespace Identity.Domain.Entities
{
    public class Permission : BaseEntity<Guid>
    {
        public string Name { get; set; }

        public string Description { get; set; }

        public ICollection<RolePermission> RolePermissions { get; set; }
    }
}