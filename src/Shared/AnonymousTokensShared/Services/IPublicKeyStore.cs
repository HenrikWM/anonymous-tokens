using Org.BouncyCastle.Crypto.Parameters;

namespace AnonymousTokensShared.Services
{
    public interface IPublicKeyStore
    {
        public ECPublicKeyParameters Get();
    }
}
