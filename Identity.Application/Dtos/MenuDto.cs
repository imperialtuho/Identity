namespace Identity.Application.Dtos
{
    public class MenuDto
    {
        public string Title { get; set; }

        public string Description { get; set; }

        public string? ParentId { get; set; }

        public string Icon { get; set; }

        public string Url { get; set; }

        public int? OrderNumber { get; set; }
    }
}