using Org.BouncyCastle.Math;

namespace AnonymousTokens.Services
{
    public interface IPrivateKeyStore
    {
        public BigInteger Get();
    }
}
