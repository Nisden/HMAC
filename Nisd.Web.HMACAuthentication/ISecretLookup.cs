namespace Nisd.Web.HMACAuthentication
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public interface ISecretLookup
    {
        Task<byte[]> LookupAsync(string id);
    }
}
