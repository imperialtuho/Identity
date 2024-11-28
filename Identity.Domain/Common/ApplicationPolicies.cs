namespace Identity.Domain.Common
{
    public static class ApplicationPolicies
    {
        public const string Super = nameof(Super);
        public const string Create = nameof(Create);
        public const string Read = nameof(Read);
        public const string Update = nameof(Update);
        public const string Delete = nameof(Delete);

        public static readonly List<string> DefaultPolicies = [Create, Read, Update, Delete];
    }
}