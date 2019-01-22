# HMAC Authentication
Simple HMAC authentication for ASP.NET Core

1. Create your own class that implements `ISecretLookup`.
```csharp
        public class ApplicationSecretLookup : ISecretLookup
        {
            private readonly ApplicationDbContext context;            

            public ApplicationSecretLookup(ApplicationDbContext context) 
            {
                this.context = context
            }

            public async Task<byte[]> LookupAsync(string id)
            {
                return (await context.Secrets.SingleOrDefaultAsync(x => x.Id == id)).SharedSecret;
            }
        }
```

2. Modify your `Startup.cs`
```csharp
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

            services.AddScoped<ISecretLookup, ApplicationSecretLookup>();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();
        }
```

3. Use the SignatureHelper to help generate an valid signature.
```csharp
// Calculate Signature
string authenticationSignature = SignatureHelper.Calculate(TestStartup.Secret, SignatureHelper.Generate(requestMessage.Headers.Date.Value, requestMessage?.Content?.Headers.ContentLength ?? 0, requestMessage.Method.Method, "/HelloWorld", ""));
requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("HMAC", TestStartup.Id + ":" + authenticationSignature);
```

## HMAC
The following values are used for generating the signature
  * Date
  * Content-Length
  * Method
  * Path
  * Query

## Nuget

[![Build status](https://ci.appveyor.com/api/projects/status/sefwyg9p87kcm3wg?svg=true)](https://ci.appveyor.com/project/NsdWorkBook/hmac)

Package feed: https://ci.appveyor.com/nuget/hmac-8ur3ps4toqs6