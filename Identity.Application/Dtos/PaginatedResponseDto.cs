using Microsoft.EntityFrameworkCore;

namespace Identity.Application.Dtos
{
    public class PaginatedResponseDto<TResponse>
    {
        public IReadOnlyCollection<TResponse> Items { get; }
        public int PageNumber { get; }
        public int TotalPages { get; }
        public int TotalCount { get; }

        public PaginatedResponseDto(IReadOnlyCollection<TResponse> items, int count, int pageNumber, int pageSize)
        {
            PageNumber = pageNumber;
            TotalPages = (int)Math.Ceiling(count / (double)pageSize);
            TotalCount = count;
            Items = items;
        }

        public bool HasPreviousPage => PageNumber > 1;

        public bool HasNextPage => PageNumber < TotalPages;

        public static async Task<PaginatedResponseDto<TResponse>> CreateAsync(IQueryable<TResponse> source, int pageNumber, int pageSize)
        {
            var count = await source.CountAsync();
            var items = await source.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToListAsync();

            return new PaginatedResponseDto<TResponse>(items, count, pageNumber, pageSize);
        }
    }
}