using Org.BouncyCastle.Crypto.Parameters;

namespace AnonymousTokensShared.Services.InMemory
{

    public class InMemoryPublicKeyStore : IPublicKeyStore
    {
        private const string ResourceFile = "public-key.pem";

        public ECPublicKeyParameters Get()
        {
            var resource = $"{EmbeddedResourceConstants.ResourceBasePath}{ResourceFile}";

            return (ECPublicKeyParameters)EmbeddedPemResource.Load(resource);
        }
    }
}
