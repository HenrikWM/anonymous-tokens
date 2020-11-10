using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

using System;
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
        public static (byte[] t, BigInteger r, ECPoint P) Initiate(ECCurve curve)
        {
            var random = new SecureRandom();

            // From GenerateKeyPair() of ECKeyPairGenerator            
            BigInteger r = curve.Field.Characteristic;
            BigInteger d;

            for (; ; )
            {
                d = new BigInteger(r.BitLength, random);

                if (d.CompareTo(BigInteger.One) < 0 || d.CompareTo(r) >= 0)
                    continue;

                break;
            }

            var t = new byte[32];
            ECPoint T;
            for (; ; )
            {
                random.NextBytes(t);
                T = HashToCurve(curve, t);

                if (T == null)
                {
                    continue;
                }

                break;
            }

            ECPoint P = T.Multiply(r);

            return (t, r, P);
        }

        /// <summary>
        /// Kjøres på verifikasjonsserveren
        /// </summary>
        /// <param name="P"></param>
        /// <param name="k"></param>
        public static void GenerateToken(ECPoint P, BigInteger k)
        {
            var Q = P.Multiply(k);
            // TODO: Så må vi lage et ZK-bevis. Det tar vi når vi har fått resten her til å fungere
        }

        public static ECPoint HashToCurve(ECCurve curve, byte[] t)
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

        static void Main(string[] args)
        {
            var ecParameters = GetECParameters("secp256k1");

            // Generate private key k and public key K.
            var keyPair = KeyGeneration.CreateKeyPair(ecParameters);

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            Console.WriteLine($"Private key:\n{ToHex(privateKey.D.ToByteArrayUnsigned())}");
            Console.WriteLine($"Public key:\n{ToHex(publicKey.Q.GetEncoded())}");

            // Sanity check
            var testPoint = ecParameters.G.Multiply(privateKey.D);
            Console.WriteLine($"\nManually:\n{ToHex(testPoint.GetEncoded())}");
            var inverseKey = privateKey.D.ModInverse(ecParameters.Curve.Order);
            var baseAgain = testPoint.Multiply(inverseKey);
            Console.WriteLine($"\nBase point:\n{ToHex(ecParameters.G.GetEncoded())}");
            Console.WriteLine($"\nHopefully base point:\n{ToHex(baseAgain.GetEncoded())}");

            // Initiate communication
            var config = Initiate(ecParameters.Curve);
            var t = config.t;

            Console.WriteLine($"t: {ToHex(t)}");

            var r = config.r;

            Console.WriteLine($"r: {ToHex(r.ToByteArrayUnsigned())}");

            var P = config.P;

            // Generate token
            GenerateToken(P, privateKey.D);

            // Randomise the token Q, by removing
            // the mask r: W = (1/r)*Q = k*P.
            // Also checks that proof (c,z) is correct.
            // TODO

            // Verify that the token (t,W) is correct.
            // TODO            
        }

    }
}
