﻿using Identity.Domain.Constants;
using Microsoft.AspNetCore.ResponseCompression;

namespace Identity.Api
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddApiServices(this IServiceCollection services, IConfiguration configuration)
        {
            const int MaxRequestBodySize = 100000000;
            string _myAllowSpecificOrigins = ApplicationConstants.MyAllowSpecificOrigins;

            // Adds CORS
            services.AddCors(options =>
            {
                options.AddPolicy(_myAllowSpecificOrigins,
                builder =>
                {
                    builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
                });
            });

            // IIS Server options
            services.Configure<IISServerOptions>(options =>
            {
                options.MaxRequestBodySize = MaxRequestBodySize;
            });

            services.AddResponseCompression(options =>
            {
                options.EnableForHttps = true;
                options.Providers.Add<BrotliCompressionProvider>();
                options.Providers.Add<GzipCompressionProvider>();
            });

            // Adds versioning
            IApiVersioningBuilder apiVersioningBuilder = services.AddApiVersioning(options =>
            {
                options.DefaultApiVersion = new ApiVersion(1, 0); // Config valid API version - This affects Swagger API version too.
                options.AssumeDefaultVersionWhenUnspecified = true;
                options.ReportApiVersions = true;
            });

            // Adds API version explorer for Swagger
            apiVersioningBuilder.AddApiExplorer(options =>
            {
                options.GroupNameFormat = "'v'VVV";
                options.SubstituteApiVersionInUrl = true;
            });

            return services;
        }
    }
}