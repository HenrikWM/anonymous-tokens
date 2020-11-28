using Org.BouncyCastle.Math;

using System.Threading.Tasks;

namespace AnonymousTokens.Services
{
    public interface IPrivateKeyStore
    {
        public Task<BigInteger> GetAsync();
    }
}
