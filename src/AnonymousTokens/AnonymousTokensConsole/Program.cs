using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
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
        private static (byte[] t, BigInteger r, ECPoint P) Initiate(ECCurve curve)
        {
            var random = new SecureRandom();

            BigInteger r = GetRandomNumber(curve, random);

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

        private static BigInteger GetRandomNumber(ECCurve curve, SecureRandom random)
        {
            BigInteger N = curve.Order;
            BigInteger r;

            // Sample random 0 < r < N
            for (; ; )
            {
                r = new BigInteger(N.BitLength, random);
                if (r.CompareTo(BigInteger.One) < 0 || r.CompareTo(N) >= 0)
                    continue;
                break;
            }

            return r;
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

        private static ECPoint RandomiseToken(ECCurve curve, ECPoint Q, BigInteger r)
        {
            var rInv = r.ModInverse(curve.Order);
            var W = Q.Multiply(rInv);
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
            // for hvert Point i argumentlista:
            // dytt Point.getEncoded() inn i SHA256(evnt.lang bytearray).I stedet for getEncoded kan man kanskje også bruke getAffineXCoord() og getAffineYCoord() sammen.Poenget er bare at man må binde seg til noe helt unikt ved punktet.
            //beregn hashen av hele greia
            //return output fra hele SHA256 som en BigInteger, .Mod(basePoint1.Curve.Order)
            return null; // TODO: implementer
        }

        private static (BigInteger c, BigInteger z) CreateProof(X9ECParameters ecParameters, BigInteger k, ECPoint K, ECPoint P, ECPoint Q)
        {
            var random = new SecureRandom();

            BigInteger r = GetRandomNumber(ecParameters.Curve, random);
            ECPoint X = ecParameters.G.Multiply(r);
            ECPoint Y = P.Multiply(r);

            BigInteger c = CreateChallenge(ecParameters.G, P, K, Q, X, Y);
            BigInteger z = r.Subtract(c.Multiply(k)).Mod(ecParameters.Curve.Order);

            return (c, z);
        }

        //VerifyProof(ecParameters, ECPoint publicKey, ECPoint P, ECPoint Q, BigInteger c, BigInteger z)

        //    ECPoint X = ecParameters.G.Multiply(z).Add(publicKey.Multiply(c));
        //        ECPoint Y = P.Multiply(z).Add(Q.Multiply(c));
        //        cPrime = CreateChallenge(ecParameters.G, P, publicKey, Q, X, Y);
        //	return c == cPrime // Hvis de to er like, så er vi fornøyd. Hvis de er like når de *skal* være like, så kan vi virkelig være godt fornøyde.

        static void Main(string[] args)
        {
            var ecParameters = GetECParameters("secp256k1");

            // Generate private key k and public key K.
            var keyPair = KeyGeneration.CreateKeyPair(ecParameters);

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
            var c = token.c;
            var z = token.z;

            // Randomise the token Q, by removing
            // the mask r: W = (1/r)*Q = k*P.
            // Also checks that proof (c,z) is correct.
            var W = RandomiseToken(ecParameters.Curve, token.Q, r);

            // Verify that the token (t,W) is correct.
            if (VerifyToken(ecParameters.Curve, t, W, privateKey.D))
            {
                Console.WriteLine("Token is valid.");
            }
            else
            {
                Console.WriteLine("Token is invalid.");
            }
        }
    }
}
