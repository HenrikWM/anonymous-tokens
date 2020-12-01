
using AnonymousTokens.Server.Protocol;
using AnonymousTokens.Services;
using AnonymousTokens.Services.InMemory;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Server.Token.Api
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            // Configure AnonymousTokens DI
            services.AddSingleton<ISeedStore, InMemorySeedStore>();
            services.AddSingleton<IPrivateKeyStore, InMemoryPrivateKeyStore>();
            services.AddSingleton<IPublicKeyStore, InMemoryPublicKeyStore>();
            services.AddSingleton<ITokenGenerator, TokenGenerator>();
            services.AddSingleton<ITokenVerifier, TokenVerifier>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
