using AnonymousTokens.Services;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

using System.Threading.Tasks;

namespace AnonymousTokens.Server.Protocol
{
    public interface ITokenVerifier
    {
        public Task<bool> VerifyTokenAsync(
            BigInteger k,
            ECCurve curve,
            byte[] t,
            ECPoint W);
    }

    public class TokenVerifier : ITokenVerifier
    {
        /// <summary>
        /// The store to save used seeds and search within for seed t.
        /// </summary>
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
        /// <param name="k">The private key for the token scheme</param>
        /// <param name="curve">Curve parameters</param>
        /// <param name="t">Seed for the initial point chosen by the initiator</param>
        /// <param name="W">Token received from the initiator</param>
        /// <returns>True if the token is valid, otherwise false</returns>
        public async Task<bool> VerifyTokenAsync(
            BigInteger k,
            ECCurve curve,
            byte[] t,
            ECPoint W)
        {
            // Check if token t is received earlier
            if (await _seedStore.ExistsAsync(t))
                return false;

            await _seedStore.SaveAsync(t);

            var T = ECCurveHash.HashToWeierstrassCurve(curve, t);
            if (T == null)
                return false;

            var V = T.Multiply(k);
            return V.Equals(W);
        }
    }
}
