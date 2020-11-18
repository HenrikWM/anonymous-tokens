using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;

namespace Client.Console.ApiClients.TokenVerification.Models
{
    public class VerifyTokenRequestModel
    {
        public string tAsHex { get; set; }
        public string WAsHex { get; set; }

        public VerifyTokenRequestModel(byte[] t, ECPoint W)
        {
            tAsHex = Hex.ToHexString(t);
            WAsHex = Hex.ToHexString(W.GetEncoded());
        }
    }
}
