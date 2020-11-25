
using Org.BouncyCastle.Math;

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace AnonymousTokens
{
    public static class CPChallengeGenerator
    {
        /// <summary>
        /// Creates the challenge for the Chaum-Pedersen protocol, using the strong Fiat-Shamir transformation.
        /// Hashes all input and a fixed domain to create an unpredictable number. Used by the initiator and token service.
        /// </summary>
        /// <param name="G">Curve generator</param>
        /// <param name="P">Randomised point on curve</param>
        /// <param name="K">Public key K = k*G</param>
        /// <param name="Q">Signature Q = k*P</param>
        /// <param name="X">Commitment X = r*G</param>
        /// <param name="Y">Commitment Y = r*P</param>
        /// <returns>A random number uniquely based on all inputs</returns>
        public static BigInteger CreateChallenge(ECPoint G, ECPoint P, ECPoint K, ECPoint Q, ECPoint X, ECPoint Y)
        {
            // Encode the ECPoint inputs
            var GEncoded = G.GetEncoded();
            var PEncoded = P.GetEncoded();
            var KEncoded = K.GetEncoded();
            var QEncoded = Q.GetEncoded();
            var XEncoded = X.GetEncoded();
            var YEncoded = Y.GetEncoded();

            // Domain separation: make sure hash is independent of other systems
            var domain = "smittestopptoken";
            var domainEncoded = Encoding.ASCII.GetBytes(domain);

            // Using concat() is best for performance: https://stackoverflow.com/a/415396
            IEnumerable<byte> points = domainEncoded
                .Concat(GEncoded)
                .Concat(PEncoded)
                .Concat(KEncoded)
                .Concat(QEncoded)
                .Concat(XEncoded)
                .Concat(YEncoded);

            var sha256 = SHA256.Create();
            var hashAsInt = new BigInteger(sha256.ComputeHash(points.ToArray()));

            return hashAsInt.Mod(G.Curve.Order);
        }
    }
}
