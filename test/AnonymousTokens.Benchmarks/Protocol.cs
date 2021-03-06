using AnonymousTokens.Client.Protocol;
using AnonymousTokens.Core.Services.InMemory;
using AnonymousTokens.Server.Protocol;

using BenchmarkDotNet.Attributes;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

using System;

namespace AnonymousTokens.Benchmarks
{
    [MemoryDiagnoser]
    public class Protocol
    {
        private X9ECParameters _ecParameters;

        private Initiator _initiator;
        private TokenGenerator _tokenGenerator;
        private TokenVerifier _tokenVerifier;

        private BigInteger _privateKey;
        private ECPublicKeyParameters _publicKey;

        private BigInteger _privateKeyGenerated;
        private ECPublicKeyParameters _publicKeyGenerated;

        [GlobalSetup]
        public void Setup()
        {
            // Import parameters for the elliptic curve prime256v1
            _ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);

            _initiator = new Initiator();
            _tokenGenerator = new TokenGenerator();
            _tokenVerifier = new TokenVerifier(new InMemorySeedStore());

            SetupWithInMemoryKeyStores();

            SetupWithGeneratedKeys();
        }

        private void SetupWithInMemoryKeyStores()
        {
            var publicKeyStore = new InMemoryPublicKeyStore();
            _publicKey = publicKeyStore.GetAsync().GetAwaiter().GetResult();

            var privateKeyStore = new InMemoryPrivateKeyStore();
            _privateKey = privateKeyStore.GetAsync().GetAwaiter().GetResult();
        }

        private void SetupWithGeneratedKeys()
        {
            var keyPair = KeyPairGenerator.CreateKeyPair(_ecParameters);

            _privateKeyGenerated = (keyPair.Private as ECPrivateKeyParameters).D;
            _publicKeyGenerated = keyPair.Public as ECPublicKeyParameters;
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
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_privateKey, _publicKey.Q, _ecParameters, P);

            // 3. Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T. Also checks that proof (c,z) is correct.
            var W = _initiator.RandomiseToken(_ecParameters, _publicKey.Q, P, Q, proofC, proofZ, r);

            // 4. Verify that the token (t,W) is correct.
            var isVerified = _tokenVerifier.VerifyTokenAsync(_privateKey, _ecParameters.Curve, t, W).GetAwaiter().GetResult();
            if (isVerified == false)
            {
                throw new Exception("Token was expected to be valid");
            }
        }

        [Benchmark]
        public void RunProtocolEndToEnd_WithGeneratedKeysAsync()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2. Generate token Q = k*P and proof (c,z) of correctness
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_privateKeyGenerated, _publicKeyGenerated.Q, _ecParameters, P);

            // 3. Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T. Also checks that proof (c,z) is correct.
            var W = _initiator.RandomiseToken(_ecParameters, _publicKeyGenerated.Q, P, Q, proofC, proofZ, r);

            // 4. Verify that the token (t,W) is correct.
            var isVerified = _tokenVerifier.VerifyTokenAsync(_privateKeyGenerated, _ecParameters.Curve, t, W).GetAwaiter().GetResult();
            if (isVerified == false)
            {
                throw new Exception("Token was expected to be valid");
            }
        }
    }
}
