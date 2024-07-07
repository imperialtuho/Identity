namespace Identity.Application.Dtos.Users
{
    public class RoleDto
    {
        public string Email { get; set; }
        public IList<string> Roles { get; set; }
    }
}