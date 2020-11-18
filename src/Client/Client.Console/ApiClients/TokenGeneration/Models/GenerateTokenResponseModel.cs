using System.Text.Json.Serialization;

namespace AnonymousTokensConsole.ApiClients.TokenGeneration.Models
{
    public class GenerateTokenResponseModel
    {
        [JsonPropertyName("qAsHex")]
        public string QAsHex { get; set; }

        [JsonPropertyName("proofCAsHex")]
        public string ProofCAsHex { get; set; }

        [JsonPropertyName("proofZAsHex")]
        public string ProofZAsHex { get; set; }
    }
}