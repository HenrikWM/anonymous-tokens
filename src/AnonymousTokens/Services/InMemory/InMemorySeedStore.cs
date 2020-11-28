
using Org.BouncyCastle.Utilities.Encoders;

using System.Collections.Generic;
using System.Threading.Tasks;

namespace AnonymousTokens.Services.InMemory
{
    public class InMemorySeedStore : ISeedStore
    {
        private static readonly HashSet<string> _storage = new HashSet<string>();

        public Task<bool> ExistsAsync(byte[] t)
        {
            var tAsHex = Hex.ToHexString(t);

            return Task.FromResult(_storage.Contains(tAsHex));
        }

        public Task<bool> SaveAsync(byte[] t)
        {
            var tAsHex = Hex.ToHexString(t);

            _storage.Add(tAsHex);

            return Task.FromResult(true);
        }
    }
}
