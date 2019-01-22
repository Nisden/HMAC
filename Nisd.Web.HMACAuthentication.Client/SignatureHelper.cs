namespace Nisd.Web.HMACAuthentication.Client
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

    public static class SignatureHelper
    {
        public static string Generate(DateTimeOffset requestDate, long contentLenght, string method, string path, string query)
        {
            if (requestDate == default(DateTimeOffset))
                throw new ArgumentException("Request date should be diffrent the default", nameof(requestDate));

            return (requestDate.ToString("r") + '\n' +
                   contentLenght + '\n' +
                   method + '\n' +
                   path + '\n' +
                   query?.TrimStart('?')).ToLower();
        }

        public static string Calculate(byte[] secret, string signature)
        {
            if (secret == null)
                throw new ArgumentNullException(nameof(secret));

            if (signature == null)
                throw new ArgumentNullException(nameof(signature));

            using (HMAC hmac = new HMACSHA256())
            {
                hmac.Key = secret;
                return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(signature)));
            }
        }
    }
}
