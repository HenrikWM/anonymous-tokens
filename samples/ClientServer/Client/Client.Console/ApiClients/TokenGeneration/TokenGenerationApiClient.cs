
using AnonymousTokensConsole.ApiClients.TokenGeneration.Models;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;

using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AnonymousTokensConsole.ApiClients.TokenGeneration
{
    public class TokenGenerationApiClient
    {
        private static readonly HttpClient _client = new HttpClient();

        private const string TokenGenerationApiUrl = "https://localhost:5001";

        public TokenGenerationApiClient()
        {
            _client.BaseAddress = new Uri(TokenGenerationApiUrl);
            _client.DefaultRequestHeaders.Add("Accept", "application/json");
        }

        public async Task<(ECPoint Q, BigInteger proofC, BigInteger proofZ)> GenerateTokenAsync(ECCurve curve, ECPoint P)
        {
            var requestUri = new Uri($"/token/generate", UriKind.Relative);

            var request = new HttpRequestMessage(HttpMethod.Post, requestUri);

            var jsonPayload = JsonSerializer.Serialize(new GenerateTokenRequestModel(P));

            request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

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
    }
}