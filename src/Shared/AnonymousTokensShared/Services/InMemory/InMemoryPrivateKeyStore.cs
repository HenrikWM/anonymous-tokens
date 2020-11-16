using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace AnonymousTokensShared.Services.InMemory
{
    public class InMemoryPrivateKeyStore : IPrivateKeyStore
    {
        public ECPrivateKeyParameters Get()
        {
            X9ECParameters p = ECNamedCurveTable.GetByName("secp256k1");

            ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(
                new BigInteger("20186677036482506117540275567393538695075300175221296989956723148347484984008"), // d
                parameters);

            return privateKeyParameters;
        }
    }
}
