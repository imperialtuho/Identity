using Identity.Application.Dtos.Permission;

namespace Identity.Application.Dtos
{
    public class RolePermissionDto
    {
        public Guid RoleId { get; set; }

        public string? Name { get; set; }

        public IList<PermissionDto> Permissions { get; set; } = [];
    }
}