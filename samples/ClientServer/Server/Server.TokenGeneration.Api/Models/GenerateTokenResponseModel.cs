using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;

namespace Server.TokenGeneration.Api.Models
{
    public class GenerateTokenResponseModel
    {
        public string QAsHex { get; set; }
        public string ProofCAsHex { get; set; }
        public string ProofZAsHex { get; set; }

        public GenerateTokenResponseModel(ECPoint Q, BigInteger proofC, BigInteger proofZ)
        {
            QAsHex = Hex.ToHexString(Q.GetEncoded());
            ProofCAsHex = Hex.ToHexString(proofC.ToByteArray());
            ProofZAsHex = Hex.ToHexString(proofZ.ToByteArray());
        }
    }
}
