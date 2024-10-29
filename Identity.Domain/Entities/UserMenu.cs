namespace Identity.Domain.Entities
{
    public class UserMenu
    {
        public Guid UserId { get; set; }

        public Guid MenuId { get; set; }

        public User User { get; set; }

        public Menu Menu { get; set; }
    }
}