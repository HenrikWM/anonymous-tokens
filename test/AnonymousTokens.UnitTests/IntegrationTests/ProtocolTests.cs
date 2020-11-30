using AnonymousTokens.Client.Protocol;
using AnonymousTokens.Server.Protocol;
using AnonymousTokens.Services.InMemory;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

using Xunit;

namespace AnonymousTokens.UnitTests.IntegrationTests
{
    public class ProtocolTests
    {
        private readonly X9ECParameters _ecParameters;

        private readonly Initiator _initiator;
        private readonly TokenGenerator _tokenGenerator;
        private readonly TokenVerifier _tokenVerifier;

        private readonly BigInteger _privateKey;
        private readonly BigInteger _wrongPrivateKey;
        private readonly ECPublicKeyParameters _publicKey;

        public ProtocolTests()
        {
            // Import parameters for the elliptic curve prime256v1
            _ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);

            var publicKeyStore = new InMemoryPublicKeyStore();
            _publicKey = publicKeyStore.GetAsync().GetAwaiter().GetResult();

            var privateKeyStore = new InMemoryPrivateKeyStore();
            _privateKey = privateKeyStore.GetAsync().GetAwaiter().GetResult();
            _wrongPrivateKey = _privateKey.Add(BigInteger.One);

            _initiator = new Initiator();
            _tokenGenerator = new TokenGenerator();
            _tokenVerifier = new TokenVerifier(new InMemorySeedStore());
        }

        [Fact]
        public async void Run()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2. Generate token Q = k*P and proof (c,z) of correctness
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_privateKey, _publicKey.Q, _ecParameters, P);

            // 3. Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T. Also checks that proof (c,z) is correct.
            var W = _initiator.RandomiseToken(_ecParameters, _publicKey, P, Q, proofC, proofZ, r);

            // 4. Verify that the token (t,W) is correct.
            var isVerified = await _tokenVerifier.VerifyTokenAsync(_privateKey, _ecParameters.Curve, t, W);
            if (isVerified == false)
            {
                Assert.True(false, "token was expected to be valid");
            }
        }

        [Fact]
        public async void Run_FailWhenSeedIsReplayed()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2. Generate token Q = k*P and proof (c,z) of correctness
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_privateKey, _publicKey.Q, _ecParameters, P);

            // 3. Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T. Also checks that proof (c,z) is correct.
            var W = _initiator.RandomiseToken(_ecParameters, _publicKey, P, Q, proofC, proofZ, r);

            // 4. Verify that the token (t,W) is correct.
            var isVerified = await _tokenVerifier.VerifyTokenAsync(_privateKey, _ecParameters.Curve, t, W);
            if (isVerified == false)
            {
                Assert.True(false, "token was expected to be valid");
            }

            // 5. Replay token verification with seed t
            isVerified = await _tokenVerifier.VerifyTokenAsync(_privateKey, _ecParameters.Curve, t, W);
            if (isVerified == true)
            {
                Assert.True(false, "token was replayed and was expected to be not valid");
            }
        }

        [Fact]
        public void Run_FailWhenKeysDontMatch()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2'. Generate invalid token and proof
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_wrongPrivateKey, _publicKey.Q, _ecParameters, P);

            // Verify the proof
            var isValid = _initiator.VerifyProof(_ecParameters, _publicKey, P, Q, proofC, proofZ);
            Assert.False(isValid, "Keys were incorrect and the proof did not get verified");
        }

        [Fact]
        public void Run_FailWhenTokenIsMalformed()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2'. Generate invalid token and proof
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_wrongPrivateKey, _publicKey.Q, _ecParameters, P);

            // Change the point Q to something else
            var changedQ = Q.Twice();

            // Try randomising the token
            var isValid = _initiator.VerifyProof(_ecParameters, _publicKey, P, changedQ, proofC, proofZ);
            Assert.False(isValid, "The token was malformed and the proof did not get verified");
        }

        [Fact]
        public void Run_FailWhenChallengeIsWrong()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2'. Generate invalid token and proof
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_wrongPrivateKey, _publicKey.Q, _ecParameters, P);

            // Change the challenge proofC to something else
            var changedC = proofC.Add(BigInteger.One);

            // Try randomising the token
            var isValid = _initiator.VerifyProof(_ecParameters, _publicKey, P, Q, changedC, proofZ);
            Assert.False(isValid, "The challenge was changed and the proof did not get verified");
        }

        [Fact]
        public void Run_FailWhenResponseIsWrong()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2'. Generate invalid token and proof
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_wrongPrivateKey, _publicKey.Q, _ecParameters, P);

            // Change the challenge proofC to something else
            var changedZ = proofZ.Add(BigInteger.One);

            // Try randomising the token
            var isValid = _initiator.VerifyProof(_ecParameters, _publicKey, P, Q, proofC, changedZ);
            Assert.False(isValid, "The response was changed and the proof did not get verified");
        }

        [Fact]
        public void Run_FailWhenPIsNotAValidPoint()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // Create a new point with invalid coordinates
            var invalidP = _ecParameters.Curve.CreatePoint(P.XCoord.ToBigInteger().Add(BigInteger.One), P.YCoord.ToBigInteger());

            // 2. Generate token Q = k*P and proof (c,z) of correctness
            try
            {
                var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_privateKey, _publicKey.Q, _ecParameters, invalidP);
            }
            catch (AnonymousTokensException)
            {
                Assert.True(true, "an invalid point should raise an exception");
            }
        }

        [Fact]
        public async void Run_FailWhenWIsInvalid()
        {
            // 1. Initiate communication with a masked point P = r*T = r*Hash(t)
            var init = _initiator.Initiate(_ecParameters.Curve);
            var t = init.t;
            var r = init.r;
            var P = init.P;

            // 2. Generate token Q = k*P and proof (c,z) of correctness
            var (Q, proofC, proofZ) = _tokenGenerator.GenerateToken(_privateKey, _publicKey.Q, _ecParameters, P);

            // 3. Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T. Also checks that proof (c,z) is correct.
            var W = _initiator.RandomiseToken(_ecParameters, _publicKey, P, Q, proofC, proofZ, r);

            // Create a new point with invalid coordinates
            var invalidW = _ecParameters.Curve.CreatePoint(W.XCoord.ToBigInteger().Add(BigInteger.One), W.YCoord.ToBigInteger());

            // Create a new point that is merely inconsistent
            var wrongW = W.Add(W);

            // 4. Try verifying (t,W).

            try
            {
                await _tokenVerifier.VerifyTokenAsync(_privateKey, _ecParameters.Curve, t, invalidW);
            }
            catch (AnonymousTokensException)
            {
                Assert.True(true, "an invalid point should raise an exception");
            }

            var isVerified = await _tokenVerifier.VerifyTokenAsync(_privateKey, _ecParameters.Curve, t, wrongW);
            Assert.False(isVerified, "a wrong point was expected to fail verification");
        }
    }
}
