using Org.BouncyCastle.Math;

using System.Threading.Tasks;

namespace AnonymousTokens.Core.Services
{
    public interface IPrivateKeyStore
    {
        public Task<BigInteger> GetAsync();
    }
}
