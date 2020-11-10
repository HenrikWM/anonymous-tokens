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

using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace AnonymousTokensConsole
{
    class Program
    {
        static string ToHex(byte[] data) => string.Concat(data.Select(x => x.ToString("x2")));

        /// <summary>
        /// Setup, kjøres på alle steder
        /// 
        /// P-256 ser ut til å ha en fin implementasjon, mens curve25519 visstnok er experimental. Hvis ikke hadde curve25519 vært førstevalget
        /// </summary>
        private static X9ECParameters GetECParameters(string algorithm)
        {
            return ECNamedCurveTable.GetByName(algorithm);
        }

        // Appen, kjøres i forbindelse med innlogging til idporten
        // t og r lagres på dingsen, P sendes til idporten        
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
        /// Kjøres på verifikasjonsserveren
        /// </summary>
        /// <param name="P"></param>
        /// <param name="k"></param>
        private static (ECPoint Q, BigInteger c, BigInteger z) GenerateToken(X9ECParameters ecParameters, ECPoint P, ECPoint K, BigInteger k)
        {
            var Q = P.Multiply(k);

            var proof = CreateProof(ecParameters, k, K, P, Q);

            return (Q, proof.c, proof.z);
        }

        private static ECPoint HashToCurve(ECCurve curve, byte[] t)
        {
            ECFieldElement temp, x, ax, x3, y, y2;

            var P = curve.Field.Characteristic;
            var sha256 = SHA256.Create();
            var hash = new BigInteger(sha256.ComputeHash(t));

            if (hash.CompareTo(BigInteger.One) < 0 || hash.CompareTo(P) >= 0)
                return null;

            x = curve.FromBigInteger(hash);     // x
            ax = x.Multiply(curve.A);           // Ax
            temp = x.Multiply(x);               // x^2
            x3 = temp.Multiply(x);              // x^3
            temp = x3.Add(ax);                  // x^3 + Ax
            y2 = temp.Add(curve.B);             // y^2 = x^3 + Ax + B
            y = y2.Sqrt();                      // y = sqrt(x^3 + Ax + B)

            if (y == null)
                return null;

            ECPoint T = curve.CreatePoint(x.ToBigInteger(), y.ToBigInteger());
            return T;
        }

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

            var rInverse = r.ModInverse(ecParameters.Curve.Order);
            var W = Q.Multiply(rInverse);
            return W;
        }

        private static bool VerifyToken(ECCurve curve, byte[] t, ECPoint W, BigInteger k)
        {
            var T = HashToCurve(curve, t);
            var V = T.Multiply(k);
            return V.Equals(W);
        }

        private static BigInteger CreateChallenge(ECPoint basePoint1, ECPoint basePoint2, ECPoint newPoint1, ECPoint newPoint2, ECPoint commitment1, ECPoint commitment2)
        {
            var basePoint1Encoded = basePoint1.GetEncoded();
            var basePoint2Encoded = basePoint2.GetEncoded();
            var newPoint1Encoded = newPoint1.GetEncoded();
            var newPoint2Encoded = newPoint2.GetEncoded();
            var commitment1Encoded = commitment1.GetEncoded();
            var commitment2Encoded = commitment2.GetEncoded();

            // using concat() best for performance: https://stackoverflow.com/a/415396
            IEnumerable<byte> points = basePoint1Encoded
                .Concat(basePoint2Encoded)
                .Concat(newPoint1Encoded)
                .Concat(newPoint2Encoded)
                .Concat(commitment1Encoded)
                .Concat(commitment2Encoded);

            var sha256 = SHA256.Create();
            var hash = new BigInteger(sha256.ComputeHash(points.ToArray()));

            return hash.Mod(basePoint1.Curve.Order);
        }

        private static (BigInteger c, BigInteger z) CreateProof(X9ECParameters ecParameters, BigInteger k, ECPoint K, ECPoint P, ECPoint Q)
        {
            var random = new SecureRandom();

            BigInteger r = RandomCurveNumberGenerator.GenerateRandomNumber(ecParameters.Curve, random);

            ECPoint X = ecParameters.G.Multiply(r);
            ECPoint Y = P.Multiply(r);

            BigInteger c = CreateChallenge(ecParameters.G, P, K, Q, X, Y);

            // Compute z = r - ck mod N
            BigInteger z = r.Subtract(c.Multiply(k)).Mod(ecParameters.Curve.Order);

            return (c, z);
        }

        private static bool VerifyProof(X9ECParameters ecParameters, ECPoint K, ECPoint P, ECPoint Q, BigInteger c, BigInteger z)
        {
            ECPoint temp, temp2, Y, X;

            // Compute zP+cQ = rP = Y
            temp = P.Multiply(z);
            temp2 = Q.Multiply(c);
            Y = temp.Add(temp2);

            // Compute zG+cK = rG = X
            temp = ecParameters.G.Multiply(z);
            temp2 = K.Multiply(c);
            X = temp.Add(temp2);

            return c.Equals(CreateChallenge(ecParameters.G, P, K, Q, X, Y));
        }

        static void Main(string[] args)
        {
            var ecParameters = GetECParameters("secp256k1");

            // Generate private key k and public key K.
            var keyPair = KeyPairGenerator.CreateKeyPair(ecParameters);

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            Console.WriteLine($"Private key:\n{ToHex(privateKey.D.ToByteArrayUnsigned())}");
            Console.WriteLine($"Public key:\n{ToHex(publicKey.Q.GetEncoded())}");

            // Initiate communication
            var config = Initiate(ecParameters.Curve);
            var t = config.t;

            Console.WriteLine($"t: {ToHex(t)}");

            var r = config.r;

            Console.WriteLine($"r: {ToHex(r.ToByteArrayUnsigned())}");

            var P = config.P;

            // Generate token
            var token = GenerateToken(ecParameters, P, publicKey.Q, privateKey.D);
            var Q = token.Q;
            var c = token.c;
            var z = token.z;

            // Randomise the token Q, by removing
            // the mask r: W = (1/r)*Q = k*P.
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
