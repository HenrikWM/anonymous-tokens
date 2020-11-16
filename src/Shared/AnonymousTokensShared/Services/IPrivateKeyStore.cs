using Org.BouncyCastle.Crypto.Parameters;

namespace AnonymousTokensShared.Services
{
    public interface IPrivateKeyStore
    {
        public ECPrivateKeyParameters Get();
    }
}
