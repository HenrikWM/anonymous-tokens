using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace AnonymousTokensShared.Services.InMemory
{
    public class InMemoryPrivateKeyStore : InMemoryStore, IPrivateKeyStore
    {
        public ECPrivateKeyParameters Get()
        {
            var keyPair = (AsymmetricCipherKeyPair)LoadPemResource("private-key.pem");

            return (ECPrivateKeyParameters)keyPair.Private;
        }
    }
}
