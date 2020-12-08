
using AnonymousTokensConsole.ApiClients.TokenApi.Models;

using Client.Console.ApiClients.TokenApi.Models;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;

using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AnonymousTokensConsole.ApiClients.TokenApi
{
    public class TokenApiClient
    {
        private HttpClient _client;

        private const string TokenApiUrl = "https://localhost:5011";

        public async Task<(ECPoint Q, BigInteger proofC, BigInteger proofZ)> GenerateTokenAsync(ECCurve curve, ECPoint P)
        {
            var requestUri = new Uri($"/api/anonymoustokens", UriKind.Relative);

            var request = new HttpRequestMessage(HttpMethod.Post, requestUri);

            var jsonPayload = JsonSerializer.Serialize(new GenerateTokenRequestModel(P));

            request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

            // Call Smittestopp2 Verification API
            _client = new HttpClient();
            _client.DefaultRequestHeaders.Add("Accept", "application/json");
            _client.BaseAddress = new Uri("https://localhost:5001/");
            _client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer <insert access token>");

            var result = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            if (result.IsSuccessStatusCode)
            {
                using var contentStream = await result.Content.ReadAsStreamAsync();
                var responseModel = await JsonSerializer.DeserializeAsync<GenerateTokenResponseModel>(contentStream, null);

                var QAsBytes = Hex.Decode(responseModel.QAsHex);
                var proofC = new BigInteger(Hex.Decode(responseModel.ProofCAsHex));
                var proofZ = new BigInteger(Hex.Decode(responseModel.ProofZAsHex));

                return (curve.DecodePoint(QAsBytes), proofC, proofZ);
            }

            throw new Exception($"Failed to generate token: {result.ReasonPhrase}.");
        }

        public async Task<bool> VerifyTokenAsync(byte[] t, ECPoint W)
        {
            var requestUri = new Uri($"/token/verify", UriKind.Relative);

            var request = new HttpRequestMessage(HttpMethod.Post, requestUri);

            var jsonPayload = JsonSerializer.Serialize(new VerifyTokenRequestModel(t, W));

            request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

            _client = new HttpClient();
            _client.DefaultRequestHeaders.Add("Accept", "application/json");
            _client.BaseAddress = new Uri("https://localhost:5011/");

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
