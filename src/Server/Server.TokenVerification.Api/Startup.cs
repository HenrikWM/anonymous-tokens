
using AnonymousTokensShared.Protocol;
using AnonymousTokensShared.Services.InMemory;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;

namespace Server.VerificationBackend
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
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
                var ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);

                var privateKeyStore = new InMemoryPrivateKeyStore();
                var privateKey = privateKeyStore.Get();

                var tokenVerifier = new TokenVerifier(privateKey);

                // TODO: verify token

                endpoints.MapPost("/token/verify", async context =>
                {
                    //var t = context.Request.Query["t"];
                    //var W = context.Request.Query["W"];

                    //// Verify that the token (t,W) is correct.
                    //if (tokenVerifier.VerifyToken(ecParameters.Curve, t, W))
                    //{
                    //    await context.Response.WriteAsync("Token valid!");
                    //}
                    //else
                    //{
                    //    await context.Response.WriteAsync("Token is invalid!");
                    //}
                });
            });
        }
    }
}
