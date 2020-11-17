
using AnonymousTokensConsole.ApiClients.TokenGeneration;

using AnonymousTokensShared.Protocol;
using AnonymousTokensShared.Services.InMemory;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;

using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace AnonymousTokensConsole
{
    class Program
    {
        /// <summary>
        /// Defines an elliptic curve to be used in our protocol.
        /// </summary>
        /// <param name="iod">The object identifier for the algorith to use.</param>
        /// <returns>
        /// Parameters including curve constants, base point, order and underlying field.
        /// Built-in functions allow us to compute scalar multiplications and point additions.
        /// </returns>
        private static X9ECParameters GetECParameters(DerObjectIdentifier oid)
        {
            return CustomNamedCurves.GetByOid(oid);
        }

        private static Initiator _initiator;
        private static TokenVerifier _tokenVerifier;

        private static TokenGenerationApiClient _tokenGenerationClient = new TokenGenerationApiClient();

        static async Task Main(string[] args)
        {
            // TODO: Get BankID JWT and add to HttpClients

            // Import parameters for the elliptic curve prime256v1
            var ecParameters = GetECParameters(X9ObjectIdentifiers.Prime256v1);

            var publicKeyStore = new InMemoryPublicKeyStore();
            var publicKey = publicKeyStore.Get();

            var privateKeyStore = new InMemoryPrivateKeyStore();
            var privateKey = privateKeyStore.Get();

            _initiator = new Initiator(publicKey);
            _tokenVerifier = new TokenVerifier(privateKey);

            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2. Generate token Q = k*P and proof (c,z) of correctness
            var (Q, proofC, proofZ) = await _tokenGenerationClient.GenerateTokenAsync(ecParameters.Curve, P);

            // 3. Verify proof (ingen hemmelig info) - kan flyttes til et bevis-API. Brukt av både TokenGenerator og Initiator(appen)
            if (_initiator.VerifyProof(ecParameters, P, Q, proofC, proofZ) == false)
            {
                throw new Exception("Unable to verify proof.");
            }

            // 4. Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T. Also checks that proof (c,z) is correct.
            var W = _initiator.RandomiseToken(ecParameters, P, Q, proofC, proofZ, r);

            // 5. Verify that the token (t,W) is correct.
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