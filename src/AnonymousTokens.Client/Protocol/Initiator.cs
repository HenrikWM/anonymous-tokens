
using AnonymousTokens.Core;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace AnonymousTokens.Client.Protocol
{
    public interface IInitiator
    {
        public (byte[] t, BigInteger r, ECPoint P) Initiate(ECCurve curve);
        public bool VerifyProof(
            X9ECParameters ecParameters,
            ECPublicKeyParameters K,
            ECPoint P,
            ECPoint Q,
            BigInteger c,
            BigInteger z);
        public ECPoint RandomiseToken(
            X9ECParameters ecParameters,
            ECPublicKeyParameters K,
            ECPoint P,
            ECPoint Q,
            BigInteger c,
            BigInteger z,
            BigInteger r);
    }

    public class Initiator : IInitiator
    {
        private readonly SecureRandom _random;

        public Initiator()
        {
            _random = new SecureRandom();
        }

        /// <summary>
        /// Used by the initiator. Generates an initial point to be submitted to the token service for signing.
        /// </summary>
        /// <param name="curve">Curve parameters</param>
        /// <returns>The seed t for a random point, the initial mask r of the point, and the masked point P</returns>
        public (byte[] t, BigInteger r, ECPoint P) Initiate(ECCurve curve)
        {
            BigInteger r = ECCurveRandomNumberGenerator.GenerateRandomNumber(curve, _random);

            // Sample random bytes t such that x = hash(t) is a valid
            // x-coordinate on the curve. Then T = HashToWeierstrassCurve(t).
            byte[]? t = new byte[32];
            ECPoint? T;
            for (; ; )
            {
                _random.NextBytes(t);
                T = ECCurveHash.HashToWeierstrassCurve(curve, t);
                if (T == null)
                    continue;
                break;
            }

            if (T == null)
                throw new AnonymousTokensException("Point T is null after unsuccessfull hashing");

            // Compute P = r*T
            ECPoint P = T.Multiply(r);
            return (t, r, P);
        }

        /// <summary>
        /// Used by the initiator. Verifies a transcript of a Chaum-Pedersen protocol instance, using the strong Fiat-Shamir transform.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="K">The public key parameters for the token scheme</param>
        /// <param name="P">Point initially submitted by the initiator</param>
        /// <param name="Q">Point received from the token service</param>
        /// <param name="c">Claimed challenge from the Chaum-Pedersen proof</param>
        /// <param name="z">Response from the Chaum-Pedersen proof</param>
        /// <returns>Returns true if the proof is valid and otherwise returns false</returns>
        public bool VerifyProof(X9ECParameters ecParameters, ECPublicKeyParameters K, ECPoint P, ECPoint Q, BigInteger c, BigInteger z)
        {
            // Compute X = z*G + c*K = r*G
            ECPoint? X = ecParameters.G.Multiply(z).Add(K.Q.Multiply(c));

            // Compute Y = z*P + c*Q = r*P
            ECPoint? Y = P.Multiply(z).Add(Q.Multiply(c));

            // Returns true if the challenge from the proof equals the new challenge
            return c.Equals(CPChallengeGenerator.CreateChallenge(ecParameters.G, P, K.Q, Q, X, Y));
        }

        /// <summary>
        /// Used by the initiator. It first verifies that the incoming token is well-formed, and then removes the previously applied mask.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="K">The public key parameters for the token scheme</param>
        /// <param name="P">Masked point initially submitted to the token service</param>
        /// <param name="Q">Signed masked point returned from the token service</param>
        /// <param name="c">Claimed challenge from the Chaum-Pedersen proof</param>
        /// <param name="z">Response from the Chaum-Pedersen proof</param>
        /// <param name="r">Masking of the initial point</param>
        /// <returns>A randomised signature W on the point chosen by the initiator</returns>
        public ECPoint RandomiseToken(X9ECParameters ecParameters, ECPublicKeyParameters K, ECPoint P, ECPoint Q, BigInteger c, BigInteger z, BigInteger r)
        {
            ECCurve? curve = ecParameters.Curve;

            // Check that P is a valid point on the currect curve
            if (ECPointVerifier.PointIsValid(P, curve) == false)
                throw new AnonymousTokensException("P is not a valid point on the curve");

            // Check that Q is a valid point on the currect curve
            if (ECPointVerifier.PointIsValid(Q, curve) == false)
                throw new AnonymousTokensException("Q is not a valid point on the curve");

            // Verify the proof (c,z).
            if (!VerifyProof(ecParameters, K, P, Q, c, z))
                throw new AnonymousTokensException("Chaum-Pedersen proof is invalid");

            // Removing the initial mask r. W = (1/r)*Q = k*T.
            BigInteger? rInverse = r.ModInverse(ecParameters.Curve.Order);
            ECPoint? W = Q.Multiply(rInverse);
            return W;
        }
    }
}
