using Org.BouncyCastle.Math;

namespace AnonymousTokensShared.Services
{
    public interface IPrivateKeyStore
    {
        public BigInteger Get();
    }
}
