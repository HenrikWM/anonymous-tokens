﻿using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

using System;
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
            random.NextBytes(t);
            ECPoint T = HashToCurve(curve, t);

            ECPoint P = T.Multiply(r);

            // Sanity check på dette tidspunktet, for å sjekke at det vi gjør gir mening. Skal ikke med i ferdig kode:
            ECFieldElement x = curve.FromBigInteger(r);
            ECFieldElement xi = x.Invert();
            var ri = xi.ToBigInteger();
            Debug.Assert(P.Multiply(ri) == T);

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
            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(t);

            // x = tolk hash som et FieldElement, i range 0 < x < ECCurve.FiniteField.order
            // Dette er i prinisppet enkelt, siden ECCurve.FiniteField.order for kurven P-256 er et 256 bit tall. 
            // Imidlertid, dersom x > ECCurve.FiniteField.order hadde det vært fristende å bare kjøre en mod-operasjon for å få x liten nok. 
            // Det vil gjøre at lave x blir litt mer sannsynlige enn høye x, og derfor et sikkerhetsproblem. Da er det bedre å returnere med feil, og be om ny tilfeldig t. OK, la oss anta at alt er i orden hittil.

            // y2 = x ^ 3 + ECCurve.a * x + ECCurve.b // Alt dette skal være FieldElement, så forhåpentligvis gjør den modulo automatisk
            // y = y2.sqrt() // Denne har 50 % sjanse for å lykkes. Hvis den ikke gjør det, be om ny tilfeldig t.

            //var T = ECCurve.CreatePoint(x, y);
            //return T;
            return curve.CreatePoint(new BigInteger(""), new BigInteger("")); // TODO: slett denne linjen, bare for å få ting til å kompilere
        }

        static void Main(string[] args)
        {
            var ecParameters = GetECParameters("secp256k1");

            // Generate private key k,
            // and public key K.
            var keyPair = KeyGeneration.CreateKeyPair(ecParameters);

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            Console.WriteLine($"Private key: {ToHex(privateKey.D.ToByteArrayUnsigned())}");
            Console.WriteLine($"Public key: {ToHex(publicKey.Q.GetEncoded())}");

            var config = Initiate(ecParameters.Curve);
            var t = config.t;
            var r = config.r;
            var P = config.P;

            // Generate token Q = k*P, and create
            // proof (c,z) of correctness, given G and K.
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
