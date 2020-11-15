﻿using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

using System;
using System.Diagnostics;

namespace AnonymousTokensShared.Protocol
{
    public class Initiator
    {
        /// <summary>
        /// Used by the initiator. Generates an initial point to be submitted to the token service for signing.
        /// </summary>
        /// <param name="curve">Curve parameters</param>
        /// <returns>The seed t for a random point, the initial mask r of the point, and the masked point P</returns>
        public (byte[] t, BigInteger r, ECPoint P) Initiate(ECCurve curve)
        {
            var random = new SecureRandom();

            BigInteger r = ECCurveRandomNumberGenerator.GenerateRandomNumber(curve, random);

            // Sample random bytes t such that x = hash(t) is a valid
            // x-coordinate on the curve. Then T = HashToCurve(t).
            var t = new byte[32];
            ECPoint T;
            for (; ; )
            {
                random.NextBytes(t);
                T = ECCurveHash.HashToCurve(curve, t);
                if (T == null)
                    continue;
                break;
            }

            // Compute P = r*T
            ECPoint P = T.Multiply(r);
            return (t, r, P);
        }

        /// <summary>
        /// Used by the initiator. It first verifies that the incoming token is well-formed, and then removes the previously applied mask.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="K">Public key for the token scheme</param>
        /// <param name="P">Masked point initially submitted to the token service</param>
        /// <param name="Q">Signed masked point returned from the token service</param>
        /// <param name="c">Claimed challenge from the Chaum-Pedersen proof</param>
        /// <param name="z">Response from the Chaum-Pedersen proof</param>
        /// <param name="r">Masking of the initial point</param>
        /// <returns>A randomised signature W on the point chosen by the initiator</returns>
        public ECPoint RandomiseToken(X9ECParameters ecParameters, ECPoint K, ECPoint P, ECPoint Q, BigInteger c, BigInteger z, BigInteger r)
        {
            // Verify the proof (c,z).
            if (VerifyProof(ecParameters, K, P, Q, c, z))
            {
                Console.WriteLine("Proof is valid.");
            }
            else
            {
                Console.WriteLine("Proof is not valid.");
                Debug.Fail("Token is invalid.");
            }

            // Removing the initial mask r. W = (1/r)*Q = k*T.
            var rInverse = r.ModInverse(ecParameters.Curve.Order);
            var W = Q.Multiply(rInverse);
            return W;
        }

        /// <summary>
        /// Used by the initiator. Verifies a transcript of a Chaum-Pedersen protocol instance, using the strong Fiat-Shamir transform.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="K">Public key for the token scheme</param>
        /// <param name="P">Point initially submitted by the initiator</param>
        /// <param name="Q">Point received from the token service</param>
        /// <param name="c">Claimed challenge from the Chaum-Pedersen proof</param>
        /// <param name="z">Response from the Chaum-Pedersen proof</param>
        /// <returns>Returns true if the proof is valid and otherwise returns false</returns>
        private bool VerifyProof(X9ECParameters ecParameters, ECPoint K, ECPoint P, ECPoint Q, BigInteger c, BigInteger z)
        {
            // Compute X = z*G + c*K = r*G
            var X = ecParameters.G.Multiply(z).Add(K.Multiply(c));

            // Compute Y = z*P + c*Q = r*P
            var Y = P.Multiply(z).Add(Q.Multiply(c));

            // Returns true if the challenge from the proof equals the new challenge
            return c.Equals(CPChallengeGenerator.CreateChallenge(ecParameters.G, P, K, Q, X, Y));
        }
    }
}
