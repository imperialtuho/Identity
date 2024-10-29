using Identity.Api.Helpers;
using Identity.Api.Middlewares.ExceptionHandler;
using Identity.Application;
using Identity.Application.Configurations.Settings;
using Identity.Domain.Constants;
using Identity.Infrastructure;
using Microsoft.Extensions.Options;

namespace Identity.Api
{
    public class Program
    {
        protected Program()
        { }

        protected static async Task Main(string[] args)
        {
            var _environmentName = ApplicationConstants.EnvironmentName;

            var builder = WebApplication.CreateBuilder(args);

            _environmentName = Environment.GetEnvironmentVariable(ApplicationConstants.AspNetCoreEnvironment) ?? ApplicationConstants.DefaultEnvironmentName;

            // Create a logger
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });

            var logger = loggerFactory.CreateLogger<Program>();

            string information = "Environment name: {0}";
            logger.LogInformation(message: information, args: _environmentName);

            builder.Configuration
                .SetBasePath(builder.Environment.ContentRootPath)
                .AddEnvironmentVariables();

            // Add services to the container.

            builder.Services.AddInfrastructureServices(builder.Configuration);
            builder.Services.AddApplicationServices(builder.Configuration);
            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            var appSettings = app.Services.GetRequiredService<IOptions<ApplicationSettings>>().Value;

            // Configure Swagger.
            if (!appSettings.IsProductionMode)
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            if (!ExceptionHandlerMiddleware.IsProductionEnvironment(builder.Environment, _environmentName))
            {
                app.UseDeveloperExceptionPage();
                app.UseExceptionHandler(
                    ExceptionHandlerMiddleware.CustomExceptionHandlerMiddleware(true, logger));
            }
            else
            {
                app.UseExceptionHandler(
                    ExceptionHandlerMiddleware.CustomExceptionHandlerMiddleware(false, logger));
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapControllers();

            await DatabaseHelper.SeedAsync(app);

            await app.RunAsync();
        }
    }
}