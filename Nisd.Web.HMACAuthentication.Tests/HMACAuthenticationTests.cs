namespace Nisd.Web.HMACAuthentication.Tests
{
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.TestHost;
    using Nisd.Web.HMACAuthentication.Client;
    using System;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Xunit;

    public class HMACAuthenticationTests
    {
        private readonly TestServer _server;
        private readonly HttpClient _client;

        public HMACAuthenticationTests()
        {
            _server = new TestServer(new WebHostBuilder()
                .UseStartup<TestStartup>());
            _client = _server.CreateClient();
        }

        [Fact]
        public async Task CanAuthenticateUsingGetAndWithoutCustomMessageHandler()
        {
            // Create request
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, "/HelloWorld");
            requestMessage.Headers.Date = DateTimeOffset.UtcNow;

            // Calculate Signature
            string authenticationSignature = SignatureHelper.Calculate(TestStartup.Secret, SignatureHelper.Generate(requestMessage.Headers.Date.Value, requestMessage?.Content?.Headers.ContentLength ?? 0, requestMessage.Method.Method, "/HelloWorld", ""));
            requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("HMAC", TestStartup.Id + ":" + authenticationSignature);

            // Send request
            var result = await _client.SendAsync(requestMessage);
            Assert.Equal(200, (int)result.StatusCode);

            Assert.Equal("Hello World!", await result.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task CanAuthenticateUsingPostAndWithoutCustomMessageHandler()
        {
            // Create request
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, "/HelloWorld");
            requestMessage.Headers.Date = DateTimeOffset.UtcNow;
            requestMessage.Content = new StringContent("Beeb boob duup");

            // Calculate Signature
            string authenticationSignature = SignatureHelper.Calculate(TestStartup.Secret, SignatureHelper.Generate(requestMessage.Headers.Date.Value, requestMessage?.Content?.Headers.ContentLength ?? 0, requestMessage.Method.Method, "/HelloWorld", ""));
            requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("HMAC", TestStartup.Id + ":" + authenticationSignature);

            // Send request
            var result = await _client.SendAsync(requestMessage);
            Assert.Equal(200, (int)result.StatusCode);

            Assert.Equal("Hello World!", await result.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task CanAuthenticateUsingPostAndQueryAndWithoutCustomMessageHandler()
        {
            // Create request
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, "/HelloWorld?Something=Lol");
            requestMessage.Headers.Date = DateTimeOffset.UtcNow;
            requestMessage.Content = new StringContent("Beeb boob duup");

            // Calculate Signature
            string authenticationSignature = SignatureHelper.Calculate(TestStartup.Secret, SignatureHelper.Generate(requestMessage.Headers.Date.Value, requestMessage?.Content?.Headers.ContentLength ?? 0, requestMessage.Method.Method, "/HelloWorld", "Something=Lol"));
            requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("HMAC", TestStartup.Id + ":" + authenticationSignature);

            // Send request
            var result = await _client.SendAsync(requestMessage);
            Assert.Equal(200, (int)result.StatusCode);

            Assert.Equal("Hello World!", await result.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task AuthenticationFailsWithoutHeader()
        {
            // Create request
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, "/HelloWorld");

            // Send request
            var result = await _client.SendAsync(requestMessage);
            Assert.Equal(403, (int)result.StatusCode);
        }

        [Fact]
        public async Task AuthenticationFailsWithInvalidHeader()
        {
            // Create request
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, "/HelloWorld");
            requestMessage.Headers.Date = DateTimeOffset.UtcNow;
            requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("HMAC", "Deeep:beep");

            // Send request
            var result = await _client.SendAsync(requestMessage);
            Assert.Equal(403, (int)result.StatusCode);
        }
    }
}
