namespace Nisd.Web.HMACAuthentication.Tests
{
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading.Tasks;

    public class TestStartup
    {
        public const string Id = "Device1";
        public static readonly byte[] Secret = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

        public TestStartup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "HMAC";
            }).AddHMACAuthentication();

            services.AddAuthorization(options =>
            {
                options.AddPolicy("AuthenticationRequired", policy =>
                {
                    policy.RequireAuthenticatedUser();
                });
            });

            services.AddScoped<ISecretLookup, TestSecretLookup>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();

            app.Run(async (context) =>
            {
                if ((await context.AuthenticateAsync()).Succeeded)
                {
                    await context.Response.WriteAsync("Hello World!");
                }
                else
                {
                    await context.ForbidAsync();
                }
            });
        }

        private class TestSecretLookup : ISecretLookup
        {
            public Task<byte[]> LookupAsync(string id)
            {
                if (id == TestStartup.Id)
                    return Task.FromResult(TestStartup.Secret);
                else
                    return Task.FromResult<byte[]>(null);
            }
        }
    }
}
