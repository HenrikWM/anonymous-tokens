using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using System;
using System.Linq;

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

        /// <summary>
        /// Generate private key k,
        /// and public key K.
        /// </summary>
        /// <param name="ecParameters">The Elliptic Curve X9ECParameters-parameters with the curve, points etc.</param>
        /// <returns>The key pair with private and public key</returns>
        private static AsymmetricCipherKeyPair KeyGeneration(X9ECParameters ecParameters)
        {
            var generator = new ECKeyPairGenerator("EC");

            var domainParams = new ECDomainParameters(ecParameters.Curve, ecParameters.G, ecParameters.N, ecParameters.H, ecParameters.GetSeed());
            var random = new SecureRandom();

            var keyGenerationParameters = new ECKeyGenerationParameters(domainParams, random);

            generator.Init(keyGenerationParameters);

            return generator.GenerateKeyPair();
        }

        static void Main(string[] args)
        {
            var ecParameters = GetECParameters("secp256k1");

            // Generate private key k,
            // and public key K.
            var keyPair = KeyGeneration(ecParameters);

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            Console.WriteLine($"Private key: {ToHex(privateKey.D.ToByteArrayUnsigned())}");
            Console.WriteLine($"Public key: {ToHex(publicKey.Q.GetEncoded())}");

            // Generate token Q = k*P, and create
            // proof (c,z) of correctness, given G and K.
            // TODO

            // Randomise the token Q, by removing
            // the mask r: W = (1/r)*Q = k*P.
            // Also checks that proof (c,z) is correct.
            // TODO

            // Verify that the token (t,W) is correct.
            // TODO            
        }

    }
}
