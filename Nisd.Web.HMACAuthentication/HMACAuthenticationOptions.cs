namespace Nisd.Web.HMACAuthentication
{
    using Microsoft.AspNetCore.Authentication;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public class HMACAuthenticationOptions : AuthenticationSchemeOptions
    {
        public const string DefaultSchema = "HMAC";

        public string Schema => DefaultSchema;

        public TimeSpan AllowedDateDrift { get; set; } = TimeSpan.FromMinutes(5);

        public Func<string, string[]> GetRolesForId { get; set; }
    }
}
