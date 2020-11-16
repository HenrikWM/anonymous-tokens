using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;

namespace AnonymousTokensShared
{
    public interface IKeyPairGenerator
    {
        public AsymmetricCipherKeyPair CreateKeyPair(X9ECParameters ecParameters);
    }
}
