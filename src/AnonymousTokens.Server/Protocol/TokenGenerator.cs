
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

using System;

using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace AnonymousTokens.Server.Protocol
{
    public interface ITokenGenerator
    {
        public (ECPoint Q, BigInteger c, BigInteger z) GenerateToken(
            BigInteger k,
            ECPoint K,
            X9ECParameters ecParameters,
            ECPoint P);
    }

    public class TokenGenerator : ITokenGenerator
    {
        /// <summary>
        /// Used by the token service. Signs the point submitted by the initiator in order to create a token, and outputs a proof of validity.
        /// </summary>
        /// <param name="k">The private key for the token scheme</param>
        /// <param name="K">The public key for the token scheme</param>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="P">Point submitted by the app</param>
        /// <returns>A signed point Q and a Chaum-Pedersen proof (c,z) proving that the point is signed correctly</returns>
        public (ECPoint Q, BigInteger c, BigInteger z) GenerateToken(
            BigInteger k,
            ECPoint K,
            X9ECParameters ecParameters,
            ECPoint P)
        {
            var curve = ecParameters.Curve;

            // Check that P is a valid point on the currect curve
            if (ECPointVerifier.PointIsValid(P, curve) == false)
                throw new Exception("P is not a valid point on the curve");

            // Compute Q = k*P
            var Q = P.Multiply(k);

            // Chaum-Pedersen proof of correct signature
            var (c, z) = CreateProof(k, K, ecParameters, P, Q);

            return (Q, c, z);
        }

        /// <summary>
        /// Used by the token service. Creates a full transcript of a Chaum-Pedersen protocol instance, using the strong Fiat-Shamir transform.
        /// The Chaum-Pedersen proof proves that the same secret key k is used to compute K = k*G and Q = k*P, without revealing k.
        /// </summary>
        /// <param name="k">The private key.</param>
        /// <param name="K">The public key.</param>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="P">Point submitted by the initiator</param>
        /// <param name="Q">Point signed using the secret key</param>
        /// <returns></returns>
        private (BigInteger c, BigInteger z) CreateProof(
            BigInteger k,
            ECPoint K,
            X9ECParameters ecParameters,
            ECPoint P,
            ECPoint Q)
        {
            var random = new SecureRandom();

            // Sample a random integer 0 < r < N
            BigInteger r = ECCurveRandomNumberGenerator.GenerateRandomNumber(ecParameters.Curve, random);

            // Computes X = r*G
            ECPoint X = ecParameters.G.Multiply(r);

            // Computes Y = r*P
            ECPoint Y = P.Multiply(r);

            BigInteger c = CPChallengeGenerator.CreateChallenge(ecParameters.G, P, K, Q, X, Y);

            // Compute proof z = r - ck mod N
            BigInteger z = r.Subtract(c.Multiply(k)).Mod(ecParameters.Curve.Order);

            return (c, z);
        }


    }
}
