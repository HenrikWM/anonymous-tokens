using Client.Console.ApiClients.TokenVerification.Models;

using Org.BouncyCastle.Math.EC;

using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Client.Console.ApiClients.TokenVerification
{
    public class TokenVerificationApiClient
    {
        private static readonly HttpClient _client = new HttpClient();

        private const string TokenVerificationApiUrl = "https://localhost:5011";

        public TokenVerificationApiClient()
        {
            _client.BaseAddress = new Uri(TokenVerificationApiUrl);
            _client.DefaultRequestHeaders.Add("Accept", "application/json");
        }

        public async Task<bool> VerifyTokenAsync(byte[] t, ECPoint W)
        {
            var requestUri = new Uri($"/token/verify", UriKind.Relative);

            var request = new HttpRequestMessage(HttpMethod.Post, requestUri);

            var jsonPayload = JsonSerializer.Serialize(new VerifyTokenRequestModel(t, W));

            request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

            var result = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            if (result.IsSuccessStatusCode)
            {
                using var contentStream = await result.Content.ReadAsStreamAsync();
                var response = await JsonSerializer.DeserializeAsync<bool>(contentStream, null);

                return response;
            }

            throw new Exception($"Failed to verify token: {result.ReasonPhrase}.");
        }
    }
}
