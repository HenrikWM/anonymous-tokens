using Org.BouncyCastle.Math;

namespace AnonymousTokens.Shared.Services
{
    public interface IPrivateKeyStore
    {
        public BigInteger Get();
    }
}
