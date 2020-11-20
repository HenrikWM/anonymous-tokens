using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace AnonymousTokensShared.Services.InMemory
{
    public class InMemoryPrivateKeyStore : IPrivateKeyStore
    {
        private const string ResourceFile = "private-key.pem";

        public BigInteger Get()
        {
            var resource = $"{EmbeddedResourceConstants.ResourceBasePath}{ResourceFile}";

            var keyPair = (AsymmetricCipherKeyPair)EmbeddedPemResource.Load(resource);

            return ((ECPrivateKeyParameters)keyPair.Private).D;
        }
    }
}
