using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace AnonymousTokensShared.Protocol
{
    public class TokenVerifier
    {
        /// <summary>
        /// Private key for the token scheme.
        /// </summary>
        private readonly BigInteger _k;

        /// <summary>
        /// Creates an instance of TokenGenerator with a key pair.
        /// </summary>        
        /// <param name="k">The private key.</param>
        public TokenVerifier(BigInteger k)
        {
            _k = k;
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
            var T = ECCurveHash.HashToWeierstrassCurve(curve, t);
            var V = T.Multiply(_k);
            return V.Equals(W);
        }
    }
}
