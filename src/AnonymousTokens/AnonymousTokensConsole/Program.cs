using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace AnonymousTokensConsole
{
    class Program
    {
        static string ToHex(byte[] data) => string.Concat(data.Select(x => x.ToString("x2")));

        /// <summary>
		/// Defines an elliptic curve to be used in our protocol. We will use "secp256k1".
		/// </summary>
		/// <param name="algorithm"></param>
		/// <returns>
		/// Parameters including curve constants, base point, order and underlying field.
		/// Built-in functions allows us to compute scalar multiplications and point additions.
		/// </returns>
        private static X9ECParameters GetECParameters(string algorithm)
        {
            return ECNamedCurveTable.GetByName(algorithm);
        }

        /// <summary>
        /// Runs on the app. Generates an initial point to be submitted to the authorities for signing.
        /// </summary>
        /// <param name="curve">Curve parameters</param>
        /// <returns>The seed for a random point, the initial mask of the point, and the masked point</returns>
        private static (byte[] t, BigInteger r, ECPoint P) Initiate(ECCurve curve)
        {
            var random = new SecureRandom();

            BigInteger r = RandomCurveNumberGenerator.GenerateRandomNumber(curve, random);

            // Sample random bytes t such that x = hash(t) is a valid
            // x-coordinate on the curve. Then T = HashToCurve(t).
            var t = new byte[32];
            ECPoint T;
            for (; ; )
            {
                random.NextBytes(t);
                T = HashToCurve(curve, t);
                if (T == null)
                    continue;
                break;
            }

            // Compute P = r*T
            ECPoint P = T.Multiply(r);
            return (t, r, P);
        }

        /// <summary>
        /// Run by the authorities. Signs the point submitted by the app in order to create a token, and outputs a proof of validity.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="P">Point submitted by the app</param>
        /// <param name="K">Public key for the token scheme</param>
        /// <param name="k">Private key for the token scheme</param>
        /// <returns>A signed point and a Chaum-Pedersen proof verifying that the point is signed correctly</returns>
        private static (ECPoint Q, BigInteger c, BigInteger z) GenerateToken(X9ECParameters ecParameters, ECPoint P, ECPoint K, BigInteger k)
        {
            // Compute Q = k*P
            var Q = P.Multiply(k);

            // Chaum-Pedersen proof of correct signature
            var proof = CreateProof(ecParameters, k, K, P, Q);

            return (Q, proof.c, proof.z);
        }

        /// <summary>
        /// Hashes a seed t into a point T on the curve. Returns null if t is unsuitable.
        /// </summary>
        /// <param name="curve">The elliptic curve in Weierstrass form</param>
        /// <param name="t">The seed</param>
        /// <returns>A random point uniquely determined by t, otherwise null</returns>
        private static ECPoint HashToCurve(ECCurve curve, byte[] t)
        {
            ECFieldElement temp, x, ax, x3, y, y2;

            var P = curve.Field.Characteristic;
            var sha256 = SHA256.Create();
            var hash = new BigInteger(sha256.ComputeHash(t));

            if (hash.CompareTo(BigInteger.One) < 0 || hash.CompareTo(P) >= 0)
                return null;

            // A valid point (x,y) must satisfy: y^2 = x^3 + Ax + B mod P
            x = curve.FromBigInteger(hash);     // x
            ax = x.Multiply(curve.A);           // Ax
            temp = x.Multiply(x);               // x^2
            x3 = temp.Multiply(x);              // x^3
            temp = x3.Add(ax);                  // x^3 + Ax
            y2 = temp.Add(curve.B);             // y^2 = x^3 + Ax + B
            y = y2.Sqrt();                      // y = sqrt(x^3 + Ax + B)

            // y == null if square root mod P does not exist
            if (y == null)
                return null;

            ECPoint T = curve.CreatePoint(x.ToBigInteger(), y.ToBigInteger());
            return T;
        }

        /// <summary>
        /// Runs on the app. It first verifies that the incoming token is well-formed, and then removes the previously applied masking.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="K">Public key for the token scheme, as published by the authorities</param>
        /// <param name="P">Masked point initially submitted to the autorities</param>
        /// <param name="Q">Signed masked point returned from the autorities</param>
        /// <param name="c">Claimed challenge from the Chaum-Pedersen proof</param>
        /// <param name="z">Response from the Chaim-Pedersen proof</param>
        /// <param name="r">App masking of the initial point</param>
        /// <returns>A signature on the random point chosen by the app</returns>
        private static ECPoint RandomiseToken(X9ECParameters ecParameters, ECPoint K, ECPoint P, ECPoint Q, BigInteger c, BigInteger z, BigInteger r)
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

            // Removing the initial mask r. W = (1/r)*Q = k*P.
            var rInverse = r.ModInverse(ecParameters.Curve.Order);
            var W = Q.Multiply(rInverse);
            return W;
        }

        /// <summary>
        /// Runs on Smittestopp backend. It recreates the intial point from the app, signes it, and verifies that they are equal.
        /// </summary>
        /// <param name="curve">Curve parameters</param>
        /// <param name="t">Seed for the initial point chosen by the app</param>
        /// <param name="W">Token received from the app</param>
        /// <param name="k">Secret key for the token scheme</param>
        /// <returns>True if the token is valid, otherwise false</returns>
        private static bool VerifyToken(ECCurve curve, byte[] t, ECPoint W, BigInteger k)
        {
            var T = HashToCurve(curve, t);
            var V = T.Multiply(k);
            return V.Equals(W);
        }

        /// <summary>
        /// Creates the challenge for the Chaum-Pedersen protocol, using the strong Fiat-Shamir transformation.
		/// Hashes all input and a fixed domain to create an unpredictable number. Used by both the app and the authorities.
        /// </summary>
        /// <param name="basePoint1">Left hand side base point</param>
        /// <param name="basePoint2">Right hand side base point</param>
        /// <param name="newPoint1">Left hand side basepoint-to-secret-exponent</param>
        /// <param name="newPoint2">Right hand side basepoint-to-secret-exponent</param>
        /// <param name="commitment1">Left hand side commitment-to-random-exponent</param>
        /// <param name="commitment2">Right hand side commitment-to-random-exponent</param>
        /// <returns>A random number based on all input</returns>
        private static BigInteger CreateChallenge(ECPoint basePoint1, ECPoint basePoint2, ECPoint newPoint1, ECPoint newPoint2, ECPoint commitment1, ECPoint commitment2)
        {
            var basePoint1Encoded = basePoint1.GetEncoded();
            var basePoint2Encoded = basePoint2.GetEncoded();
            var newPoint1Encoded = newPoint1.GetEncoded();
            var newPoint2Encoded = newPoint2.GetEncoded();
            var commitment1Encoded = commitment1.GetEncoded();
            var commitment2Encoded = commitment2.GetEncoded();

            // Domain separation: make sure hash is independent of other systems
            var domain = "smittestopptoken";
            var domainEncoded = Encoding.ASCII.GetBytes(domain);

            // Using concat() is best for performance: https://stackoverflow.com/a/415396
            IEnumerable<byte> points = domainEncoded
                .Concat(basePoint1Encoded)
                .Concat(basePoint2Encoded)
                .Concat(newPoint1Encoded)
                .Concat(newPoint2Encoded)
                .Concat(commitment1Encoded)
                .Concat(commitment2Encoded);

            var sha256 = SHA256.Create();
            var hash = new BigInteger(sha256.ComputeHash(points.ToArray()));

            return hash.Mod(basePoint1.Curve.Order);
        }

        /// <summary>
        /// Run by the authorities. Creates a full transcript of a Chaum-Pedersen protocol instance, using the strong Fiat-Shamir transform.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="k">Secret key for the token scheme, the value of which we prove existence and usage</param>
        /// <param name="K">Public key for the token scheme</param>
        /// <param name="P">Point submitted by the app</param>
        /// <param name="Q">Point signed using the secret key</param>
        /// <returns></returns>
        private static (BigInteger c, BigInteger z) CreateProof(X9ECParameters ecParameters, BigInteger k, ECPoint K, ECPoint P, ECPoint Q)
        {
            var random = new SecureRandom();

            // Sample a random integer 0 < r < N
            BigInteger r = RandomCurveNumberGenerator.GenerateRandomNumber(ecParameters.Curve, random);

            // Computes X = r*G
            ECPoint X = ecParameters.G.Multiply(r);

            // Computes Y = r*P
            ECPoint Y = P.Multiply(r);

            BigInteger c = CreateChallenge(ecParameters.G, P, K, Q, X, Y);

            // Compute proof z = r - ck mod N
            BigInteger z = r.Subtract(c.Multiply(k)).Mod(ecParameters.Curve.Order);

            return (c, z);
        }

        /// <summary>
        /// Runs in the app. Verifies a transcript of a Chaum-Pedersen protocol instance, using the strong Fiat-Shamir transform.
        /// </summary>
        /// <param name="ecParameters">Curve parameters</param>
        /// <param name="K">Public key for the token scheme</param>
        /// <param name="P">Point initially submitted by the app</param>
        /// <param name="Q">Point received from the authorities</param>
        /// <param name="c">Claimed challenge from the Chaum-Pedersen proof</param>
        /// <param name="z">Response from the Chaim-Pedersen proof</param>
        /// <returns></returns>
        private static bool VerifyProof(X9ECParameters ecParameters, ECPoint K, ECPoint P, ECPoint Q, BigInteger c, BigInteger z)
        {
            ECPoint temp, temp2, Y, X;

            // Compute z*G + c*K = r*G = X
            temp = ecParameters.G.Multiply(z);
            temp2 = K.Multiply(c);
            X = temp.Add(temp2);

            // Compute z*P + c*Q = r*P = Y
            temp = P.Multiply(z);
            temp2 = Q.Multiply(c);
            Y = temp.Add(temp2);

            // Returns true if the challenge from the proof equals the new challenge
            return c.Equals(CreateChallenge(ecParameters.G, P, K, Q, X, Y));
        }

        static void Main(string[] args)
        {
            var ecParameters = GetECParameters("secp256k1");

            // Generate private key k and public key K = k*G
            var keyPair = KeyPairGenerator.CreateKeyPair(ecParameters);

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            Console.WriteLine($"Private key:\n{ToHex(privateKey.D.ToByteArrayUnsigned())}");
            Console.WriteLine($"Public key:\n{ToHex(publicKey.Q.GetEncoded())}");

            // Initiate communication with a masked point P = r*T = r*Hash(t)
            var config = Initiate(ecParameters.Curve);
            var t = config.t;

            Console.WriteLine($"t: {ToHex(t)}");

            var r = config.r;
            var P = config.P;

            // Generate token Q = k*P and proof (c,z) of correctness
            var token = GenerateToken(ecParameters, P, publicKey.Q, privateKey.D);
            var Q = token.Q;
            var c = token.c;
            var z = token.z;

            // Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*P.
            // Also checks that proof (c,z) is correct.
            var W = RandomiseToken(ecParameters, publicKey.Q, P, Q, c, z, r);

            // Verify that the token (t,W) is correct.
            if (VerifyToken(ecParameters.Curve, t, W, privateKey.D))
            {
                Console.WriteLine("Token is valid.");
            }
            else
            {
                Console.WriteLine("Token is invalid.");
                Debug.Fail("Token is invalid.");
            }
        }
    }
}
