namespace Identity.Application.Dtos.Permission
{
    public class PermissionAddRequest
    {
        public required string Name { get; set; }
        public string? Description { get; set; }
    }
}