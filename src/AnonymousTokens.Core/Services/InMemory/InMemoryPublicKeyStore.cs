using Org.BouncyCastle.Crypto.Parameters;

using System.Threading.Tasks;

namespace AnonymousTokens.Core.Services.InMemory
{
    public class InMemoryPublicKeyStore : IPublicKeyStore
    {
        private const string ResourceFile = "public-key.pem";

        public Task<ECPublicKeyParameters> GetAsync()
        {
            var resource = $"{EmbeddedResourceConstants.ResourceBasePath}{ResourceFile}";

            return Task.FromResult((ECPublicKeyParameters)EmbeddedPemResource.Load(resource));
        }
    }
}
