using AnonymousTokens.Protocol;
using AnonymousTokens.Server.Protocol;
using AnonymousTokens.Services.InMemory;

using BenchmarkDotNet.Attributes;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;

using System;

namespace AnonymousTokens.Benchmarks
{
    [MemoryDiagnoser]
    public class Protocol
    {
        private Initiator _initiator;
        private TokenGenerator _tokenGenerator;
        private TokenVerifier _tokenVerifier;
        private X9ECParameters _ecParameters;

        [GlobalSetup]
        public void Setup()
        {
            // Import parameters for the elliptic curve prime256v1
            _ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);

            var publicKeyStore = new InMemoryPublicKeyStore();
            var publicKey = publicKeyStore.Get();

            var privateKeyStore = new InMemoryPrivateKeyStore();
            var privateKey = privateKeyStore.Get();

            _initiator = new Initiator(publicKey);
            _tokenGenerator = new TokenGenerator(publicKey, privateKey);
            _tokenVerifier = new TokenVerifier(privateKey, new InMemorySeedStore());
        }

        [Benchmark(Baseline = true)]
        public void RunProtocolEndToEnd()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2. Generate token Q = k*P and proof (c,z) of correctness
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_ecParameters, P);

            // 3. Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T. Also checks that proof (c,z) is correct.
            var W = _initiator.RandomiseToken(_ecParameters, P, Q, proofC, proofZ, r);

            // 4. Verify that the token (t,W) is correct.
            var isVerified = _tokenVerifier.VerifyToken(_ecParameters.Curve, t, W);
            if (isVerified == false)
            {
                throw new Exception("Token was expected to be valid");
            }
        }
    }
}