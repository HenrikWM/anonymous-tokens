using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;

namespace AnonymousTokensConsole.ApiClients.TokenApi.Models
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
