using Org.BouncyCastle.Crypto.Parameters;

using System.Threading.Tasks;

namespace AnonymousTokens.Core.Services
{
    public interface IPublicKeyStore
    {
        public Task<ECPublicKeyParameters> GetAsync();
    }
}
