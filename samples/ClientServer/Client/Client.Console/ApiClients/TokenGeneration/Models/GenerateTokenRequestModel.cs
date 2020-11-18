using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;

namespace AnonymousTokensConsole.ApiClients.TokenGeneration.Models
{
    public class GenerateTokenRequestModel
    {
        public string PAsHex { get; set; }

        public GenerateTokenRequestModel(ECPoint P)
        {
            PAsHex = Hex.ToHexString(P.GetEncoded());
        }
    }
}