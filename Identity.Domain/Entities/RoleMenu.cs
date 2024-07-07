namespace Identity.Domain.Entities
{
    public class RoleMenu
    {
        public string RoleId { get; set; }

        public Role Role { get; set; }

        public string MenuId { get; set; }

        public Menu Menu { get; set; }
    }
}