using AnonymousTokens.Services;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace AnonymousTokens.Server.Protocol
{
    public class TokenVerifier
    {
        /// <summary>
        /// Private key for the token scheme.
        /// </summary>
        private readonly BigInteger _k;
        private readonly ISeedStore _seedStore;

        /// <summary>
        /// Creates an instance of TokenGenerator with the private key and a store for t.
        /// </summary>
        /// <param name="k">The private key.</param>
        /// <param name="seedStore">The storage for t.</param>
        public TokenVerifier(BigInteger k, ISeedStore seedStore)
        {
            _k = k;
            _seedStore = seedStore;
        }

        /// <summary>
        /// Used by the token verifier. It recreates the initial point from the initiator, signs it, and verifies that they are equal.
        /// </summary>
        /// <param name="curve">Curve parameters</param>
        /// <param name="t">Seed for the initial point chosen by the initiator</param>
        /// <param name="W">Token received from the initiator</param>
        /// <returns>True if the token is valid, otherwise false</returns>
        public bool VerifyToken(ECCurve curve, byte[] t, ECPoint W)
        {
            // Check if token t is received earlier
            if (_seedStore.Exists(t))
                return false;

            _seedStore.Save(t);

            var T = ECCurveHash.HashToWeierstrassCurve(curve, t);
            if (T == null)
                return false;

            var V = T.Multiply(_k);
            return V.Equals(W);
        }
    }
}
