
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
            _client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkRBOTg5RTI1QzYxRTBFRUYxNTU1MzA2MUJFREIwNUFGIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MDc0Mjg1MjYsImV4cCI6MTYwNzQzMjEyNiwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwMSIsImF1ZCI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDEvcmVzb3VyY2VzIiwiY2xpZW50X2lkIjoidGVzdC1zcGEtY2xpZW50Iiwic3ViIjoiZjQ2MjAyODMtZWI5Yy00NjU4LWE2YTUtMTRkZGZhODRjMTFjIiwiYXV0aF90aW1lIjoxNjA3NDI4NTIzLCJpZHAiOiJpZHBvcnRlbiIsImNvdmlkMTlfc3RhdHVzIjoicG9zaXRpdiIsImNvdmlkMTlfYmxva2VyZXQiOiJmYWxzZSIsImNvdmlkMTlfYW5vbnltb3VzX3Rva2VuIjoiYXZhaWxhYmxlIiwiY292aWQxOV9zbWl0dGVfc3RhcnQiOiIyMDIwLTExLTMwIiwianRpIjoiRTkwMjg4MTAzMjg1M0Y4OTVENENCNzNFMEY2NjFBMTciLCJzaWQiOiIzRkQxMDk4NTg0RTQyMzExNTVGRDc5NUVBQkM0N0I3RiIsImlhdCI6MTYwNzQyODUyNiwic2NvcGUiOlsib3BlbmlkIiwic21pdHRlc3RvcCJdLCJhbXIiOlsiZXh0ZXJuYWwiXX0.nX-zwIHNo7zgh_SVnjTfZq57w-6WS8bQfdBS4z4z60NBGntIRUf8OnpSTsVJCtRCy9WgI_9kir8ZygBzktYAJYFgRJNmzN6Yl93nZI8y80t_tmtEGpBq8jQbu4dkRzUPCNDuNwLh4LUjXPoEwCTEZodEYBp4ogsBG0PS_j7yDLWlodW05j2-Sns-9iRiNuoF_WLxKS0RHmIChR3MaLKA4PXZunC4RJTi3EinbUy3nMhhvAtbo3iOLpRlBVXqChzofjr8xbt1IqbF6sXzQaeUJObHU898knEONSQSmm4Xtr8-2O_8FrM6ewpPBNP4kYL__LhaFWsyFTSdBzKeEUpcUw");

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
