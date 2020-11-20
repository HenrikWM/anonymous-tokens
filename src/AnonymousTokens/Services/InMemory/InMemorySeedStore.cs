using Org.BouncyCastle.Utilities.Encoders;

using System.Collections.Generic;

namespace AnonymousTokensShared.Services.InMemory
{
    public class InMemorySeedStore : ISeedStore
    {
        private static readonly HashSet<string> _storage = new HashSet<string>();

        public bool Exists(byte[] t)
        {
            var tAsHex = Hex.ToHexString(t);

            return _storage.Contains(tAsHex);
        }

        public bool Save(byte[] t)
        {
            var tAsHex = Hex.ToHexString(t);

            _storage.Add(tAsHex);

            return true;
        }
    }
}
