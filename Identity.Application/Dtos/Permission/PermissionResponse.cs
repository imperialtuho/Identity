using Identity.Application.Dtos.Base;

namespace Identity.Application.Dtos.Permission
{
    public class PermissionResponse : BaseDto
    {
        public Guid Id { get; set; }
        public string? Name { get; set; }
        public string? Description { get; set; }
    }
}