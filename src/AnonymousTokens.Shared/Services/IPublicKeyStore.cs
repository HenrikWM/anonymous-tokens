using Org.BouncyCastle.Crypto.Parameters;

namespace AnonymousTokens.Shared.Services
{
    public interface IPublicKeyStore
    {
        public ECPublicKeyParameters Get();
    }
}
