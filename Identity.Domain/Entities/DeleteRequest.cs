namespace Identity.Domain.Entities
{
    public class DeleteRequest : BaseEntity<Guid>
    {
        public string Reason { get; set; }

        public string Status { get; set; }


    }
}