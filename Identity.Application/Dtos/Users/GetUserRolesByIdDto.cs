namespace Identity.Application.Dtos.Users
{
    public class GetUserRolesByIdDto
    {
        public string Id { get; set; }

        public string Name { get; set; }

        public string Email { get; set; }

        public IList<string> Roles { get; set; }
    }
}