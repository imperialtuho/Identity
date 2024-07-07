namespace Identity.Domain.Entities
{
    public class UserMenu
    {
        public string UserId { get; set; }

        public string MenuId { get; set; }

        public User User { get; set; }

        public Menu Menu { get; set; }
    }
}