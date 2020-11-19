using Org.BouncyCastle.Crypto.Parameters;

namespace AnonymousTokens.Services
{
    public interface IPublicKeyStore
    {
        public ECPublicKeyParameters Get();
    }
}
