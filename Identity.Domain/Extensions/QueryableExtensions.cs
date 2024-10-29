using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Identity.Domain.Extensions
{
    public static class QueryableExtensions
    {
        public static IQueryable<T> IncludeAllNavigations<T>(this IQueryable<T> query, DbContext dbContext) where T : class
        {
            IEntityType? entityType = dbContext.Model.FindEntityType(typeof(T)) ?? throw new InvalidOperationException($"Entity type {typeof(T).Name} not found in the model.");
            IEnumerable<INavigation> navigations = entityType.GetNavigations();

            foreach (INavigation navigation in navigations)
            {
                query = query.Include(navigation.Name);
            }

            return query;
        }
    }
}