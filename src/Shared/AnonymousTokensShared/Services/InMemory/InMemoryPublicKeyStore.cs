using Org.BouncyCastle.Crypto.Parameters;

namespace AnonymousTokensShared.Services.InMemory
{

    public class InMemoryPublicKeyStore : InMemoryStore, IPublicKeyStore
    {
        public ECPublicKeyParameters Get()
        {
            return (ECPublicKeyParameters)LoadPemResource("public-key.pem");
        }
    }
}
