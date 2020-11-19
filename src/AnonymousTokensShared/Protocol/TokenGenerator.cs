using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace AnonymousTokensShared.Protocol
{
    public class TokenGenerator
    {
        /// <summary>
        /// Private key for the token scheme.
        /// </summary>
        private readonly BigInteger _k;

        /// <summary>
        /// Public key for the token scheme.
        /// </summary>
        private readonly ECPoint _K;

        /// <summary>
        /// Creates an instance of TokenGenerator with a key pair.
        /// </summary>
        /// <param name="publicKeyParameters">Parameters containing the public key K.</param>
        /// <param name="k">The private key.</param>
        public TokenGenerator(ECPublicKeyParameters publicKeyParameters, BigInteger k)
        {
            _k = k;
            _K = publicKeyParameters.Q;
        }

        /// <summary>
        /// Used by the token service. Signs the point submitted by the initiator in order to create a token, and outputs a proof of validity.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="P">Point submitted by the app</param>
        /// <returns>A signed point Q and a Chaum-Pedersen proof (c,z) proving that the point is signed correctly</returns>
        public (ECPoint Q, BigInteger c, BigInteger z) GenerateToken(X9ECParameters ecParameters, ECPoint P)
        {
            var curve = ecParameters.Curve;

            // Check that P is a valid point on the currect curve
            if (ECPointVerifier.PointIsValidOnCurve(P, curve) == false)
                return (null, BigInteger.Zero, BigInteger.Zero);

            // Compute Q = k*P
            var Q = P.Multiply(_k);

            // Chaum-Pedersen proof of correct signature
            var (c, z) = CreateProof(ecParameters, P, Q);

            return (Q, c, z);
        }

        /// <summary>
        /// Used by the token service. Creates a full transcript of a Chaum-Pedersen protocol instance, using the strong Fiat-Shamir transform.
        /// The Chaum-Pedersen proof proves that the same secret key k is used to compute K = k*G and Q = k*P, without revealing k.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>        
        /// <param name="P">Point submitted by the initiator</param>
        /// <param name="Q">Point signed using the secret key</param>
        /// <returns></returns>
        private (BigInteger c, BigInteger z) CreateProof(X9ECParameters ecParameters, ECPoint P, ECPoint Q)
        {
            var random = new SecureRandom();

            // Sample a random integer 0 < r < N
            BigInteger r = ECCurveRandomNumberGenerator.GenerateRandomNumber(ecParameters.Curve, random);

            // Computes X = r*G
            ECPoint X = ecParameters.G.Multiply(r);

            // Computes Y = r*P
            ECPoint Y = P.Multiply(r);

            BigInteger c = CPChallengeGenerator.CreateChallenge(ecParameters.G, P, _K, Q, X, Y);

            // Compute proof z = r - ck mod N
            BigInteger z = r.Subtract(c.Multiply(_k)).Mod(ecParameters.Curve.Order);

            return (c, z);
        }


    }
}
