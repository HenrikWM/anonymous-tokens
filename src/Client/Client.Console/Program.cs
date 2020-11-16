using AnonymousTokensShared;
using AnonymousTokensShared.Protocol;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;

using System;
using System.Diagnostics;

namespace AnonymousTokensConsole
{
    class Program
    {
        /// <summary>
        /// Defines an elliptic curve to be used in our protocol. We will use "secp256k1".
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns>
        /// Parameters including curve constants, base point, order and underlying field.
        /// Built-in functions allow us to compute scalar multiplications and point additions.
        /// </returns>
        private static X9ECParameters GetECParameters(string algorithm)
        {
            return ECNamedCurveTable.GetByName(algorithm);
        }

        private static TokenGenerator _tokenGenerator;
        private static Initiator _initiator;
        private static TokenVerifier _tokenVerifier;

        static void Main(string[] args)
        {
            // Import parameters for the elliptic curve secp256k1
            var ecParameters = GetECParameters("secp256k1");

            // Generate private key k and public key K = k*G
            var keyPair = KeyPairGenerator.CreateKeyPair(ecParameters);

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            _tokenGenerator = new TokenGenerator(publicKey, privateKey);
            _tokenVerifier = new TokenVerifier(privateKey);
            _initiator = new Initiator(publicKey);

            // Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // Generate token Q = k*P and proof (c,z) of correctness
            var token = _tokenGenerator.GenerateToken(ecParameters, P);
            var Q = token.Q;
            var c = token.c;
            var z = token.z;

            // Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T.
            // Also checks that proof (c,z) is correct.
            var W = _initiator.RandomiseToken(ecParameters, P, Q, c, z, r);

            // Verify that the token (t,W) is correct.
            if (_tokenVerifier.VerifyToken(ecParameters.Curve, t, W))
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
