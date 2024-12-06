﻿using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Identity.Api.Extensions
{
    public class PathPrefixInsertDocumentFilter(string prefix, bool isExposed) : IDocumentFilter
    {
        public void Apply(OpenApiDocument swaggerDoc, DocumentFilterContext context)
        {
            if (!isExposed)
            {
                // Api path (endpoint) filter.
                List<KeyValuePair<string, OpenApiPathItem>> paths = [.. swaggerDoc.Paths];
                paths.ForEach(p => swaggerDoc.Paths.Remove(p.Key));

                // Api schema (model) filter.
                List<KeyValuePair<string, OpenApiSchema>> schemas = [.. swaggerDoc.Components.Schemas];
                schemas.ForEach(s => swaggerDoc.Components.Schemas.Remove(s.Key));
            }
            else
            {
                // Add prefix
                List<string> pathKeys = [.. swaggerDoc.Paths.Keys];
                foreach (string path in pathKeys)
                {
                    OpenApiPathItem pathToChange = swaggerDoc.Paths[path];
                    swaggerDoc.Paths.Remove(path);
                    swaggerDoc.Paths.Add($"{prefix}{path}", pathToChange);
                }
            }
        }
    }
}