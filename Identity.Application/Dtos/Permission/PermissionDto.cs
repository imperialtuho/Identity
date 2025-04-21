using Identity.Application.Dtos.Base;

namespace Identity.Application.Dtos.Permission
{
    public class PermissionDto : BaseDto
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
    }
}