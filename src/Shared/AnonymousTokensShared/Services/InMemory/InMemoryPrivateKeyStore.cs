using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace AnonymousTokensShared.Services.InMemory
{
    public class InMemoryPrivateKeyStore : InMemoryStore, IPrivateKeyStore
    {
        public BigInteger Get()
        {
            var keyPair = (AsymmetricCipherKeyPair)LoadPemResource("private-key.pem");

            return ((ECPrivateKeyParameters)keyPair.Private).D;
        }
    }
}
