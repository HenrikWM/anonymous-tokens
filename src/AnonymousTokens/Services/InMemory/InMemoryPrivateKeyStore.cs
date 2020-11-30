using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

using System.Threading.Tasks;

namespace AnonymousTokens.Services.InMemory
{
    public class InMemoryPrivateKeyStore : IPrivateKeyStore
    {
        private const string ResourceFile = "private-key.pem";

        public Task<BigInteger> GetAsync()
        {
            var resource = $"{EmbeddedResourceConstants.ResourceBasePath}{ResourceFile}";

            var keyPair = (AsymmetricCipherKeyPair)EmbeddedPemResource.Load(resource);

            return Task.FromResult(((ECPrivateKeyParameters)keyPair.Private).D);
        }
    }
}
