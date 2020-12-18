
using AnonymousTokens.Client.Protocol;
using AnonymousTokens.Core.Services.InMemory;

using AnonymousTokensConsole.ApiClients.TokenApi;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;

using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace AnonymousTokensConsole
{
    class Program
    {
        private static Initiator _initiator;

        private static readonly TokenApiClient _tokenApiClient = new TokenApiClient();

        static async Task Main(string[] args)
        {
            // Import parameters for the elliptic curve prime256v1
            var ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);

            var publicKeyStore = new InMemoryPublicKeyStore();
            var publicKey = await publicKeyStore.GetAsync();

            _initiator = new Initiator();

            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2. Generate token Q = k*P and proof (c,z) of correctness
            var (Q, proofC, proofZ) = await _tokenApiClient.GenerateTokenAsync(ecParameters.Curve, P);

            // 3. Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T. Also checks that proof (c,z) is correct.
            var W = _initiator.RandomiseToken(ecParameters, publicKey, P, Q, proofC, proofZ, r);

            // 4. Verify that the token (t,W) is correct.
            var isVerified = await _tokenApiClient.VerifyTokenAsync(t, W);
            if (isVerified)
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
