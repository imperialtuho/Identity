namespace Identity.Application.Dtos
{
    public class SearchRequest
    {
        public string? Keyword { get; set; }

        public int PageSize { get; set; }

        public int PageIndex { get; set; }
    }
}