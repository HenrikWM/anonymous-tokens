using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace AnonymousTokensShared.Services.InMemory
{
    public class InMemoryPublicKeyStore : IPublicKeyStore
    {
        public ECPublicKeyParameters Get()
        {
            X9ECParameters p = ECNamedCurveTable.GetByName("secp256k1");

            ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(
               parameters.Curve.DecodePoint(Hex.Decode("03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D")), // Q
               parameters);

            return publicKeyParameters;
        }
    }
}
