namespace Identity.Application.Dtos.Users
{
    public class UserRoleDto
    {
        public string Email { get; set; }
        public IList<string> Roles { get; set; }
    }
}