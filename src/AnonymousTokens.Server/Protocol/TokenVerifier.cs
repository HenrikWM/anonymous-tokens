using AnonymousTokens.Services;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace AnonymousTokens.Server.Protocol
{
    public class TokenVerifier
    {
        private readonly ISeedStore _seedStore;

        /// <summary>
        /// Creates an instance of TokenGenerator with the private key and a store for t.
        /// </summary>
        /// <param name="seedStore">The storage for t.</param>
        public TokenVerifier(ISeedStore seedStore)
        {
            _seedStore = seedStore;
        }

        /// <summary>
        /// Used by the token verifier. It recreates the initial point from the initiator, signs it, and verifies that they are equal.
        /// </summary>
        /// <param name="k">The private key for the scheme</param>
        /// <param name="curve">Curve parameters</param>
        /// <param name="t">Seed for the initial point chosen by the initiator</param>
        /// <param name="W">Token received from the initiator</param>
        /// <returns>True if the token is valid, otherwise false</returns>
        public bool VerifyToken(BigInteger k, ECCurve curve, byte[] t, ECPoint W)
        {
            // Check if token t is received earlier
            if (_seedStore.Exists(t))
                return false;

            // Check that W is a valid point on the currect curve
            if (ECPointVerifier.PointIsValid(W, curve) == false)
                throw new AnonymousTokensException("W is not a valid point on the curve");

            _seedStore.Save(t);

            ECPoint? T = ECCurveHash.HashToWeierstrassCurve(curve, t);
            if (T == null)
                return false;

            ECPoint? V = T.Multiply(k);
            return V.Equals(W);
        }
    }
}
