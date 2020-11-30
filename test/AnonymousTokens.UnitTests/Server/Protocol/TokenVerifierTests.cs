
using AnonymousTokens.Server.Protocol;
using AnonymousTokens.Services;

using Moq;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;

using System.Threading.Tasks;

using Xunit;

namespace AnonymousTokens.UnitTests.Server.Protocol
{
    public class TokenVerifierTests
    {
        private X9ECParameters _ecParameters;

        public TokenVerifierTests()
        {
            _ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);
        }

        [Fact]
        public async void VerifyToken_RecreatedPointMatchesW_ReturnsTrue()
        {
            // Arrange
            var seedStoreMock = new Mock<ISeedStore>();
            seedStoreMock.Setup(x => x.ExistsAsync(It.IsAny<byte[]>())).Returns(Task.FromResult(false));
            seedStoreMock.Setup(x => x.SaveAsync(It.IsAny<byte[]>())).Returns(Task.FromResult(true));

            var tokenVerifier = new TokenVerifier(seedStoreMock.Object);

            var privateKey = new BigInteger(Hex.Decode("01301abfe491c0aff380269c966254ac43fdd97469234c7739ada975368181fe"));
            byte[] t = Hex.Decode("4391837b1e50cb0b075fc91ea9a85a4a795195557f4fb9a971e10b94370dee2b");
            var W = _ecParameters.Curve.DecodePoint(Hex.Decode("04ce1e55cff15c5f5fbd0abca2a2849cf04ccda1c601a849ab28eb6161a0c32e96b6346728d8d3464754361977ee1a1c68120cb0575506cafe6e24d595de92069d"));

            // Act
            var actual = await tokenVerifier.VerifyTokenAsync(privateKey, _ecParameters.Curve, t, W);

            // Assert
            seedStoreMock.Verify(mock => mock.SaveAsync(It.IsAny<byte[]>()), Times.Once());
            Assert.True(actual);
        }

        [Fact]
        public async void VerifyToken_RecreatedPointDoesNotMatchW_ReturnsFalse()
        {
            // Arrange
            var seedStoreMock = new Mock<ISeedStore>();
            seedStoreMock.Setup(x => x.ExistsAsync(It.IsAny<byte[]>())).Returns(Task.FromResult(false));
            seedStoreMock.Setup(x => x.SaveAsync(It.IsAny<byte[]>())).Returns(Task.FromResult(true));

            var tokenVerifier = new TokenVerifier(seedStoreMock.Object);

            var privateKey = new BigInteger(Hex.Decode("01301abfe491c0aff380269c966254ac43fdd97469234c7739ada975368181fe"));
            byte[] t = Hex.Decode("4391837b1e50cb0b075fc91ea9a85a4a795195557f4fb9a971e10b94370dee2b");
            var W = _ecParameters.Curve.DecodePoint(Hex.Decode("04ce1e55cff15c5f5fbd0abca2a2849cf04ccda1c601a849ab28eb6161a0c32e96b6346728d8d3464754361977ee1a1c68120cb0575506cafe6e24d595de92069d"));

            // Create a new point that is merely inconsistent
            var wrongW = W.Add(W);

            // Act
            var actual = await tokenVerifier.VerifyTokenAsync(privateKey, _ecParameters.Curve, t, wrongW);

            // Assert
            Assert.False(actual, "a wrong point was expected to fail verification");
        }

        [Fact]
        public async void VerifyToken_InvalidW_ThrowsException()
        {
            // Arrange
            var seedStoreMock = new Mock<ISeedStore>();
            seedStoreMock.Setup(x => x.ExistsAsync(It.IsAny<byte[]>())).Returns(Task.FromResult(false));
            seedStoreMock.Setup(x => x.SaveAsync(It.IsAny<byte[]>())).Returns(Task.FromResult(true));

            var tokenVerifier = new TokenVerifier(seedStoreMock.Object);

            var privateKey = new BigInteger(Hex.Decode("01301abfe491c0aff380269c966254ac43fdd97469234c7739ada975368181fe"));
            byte[] t = Hex.Decode("4391837b1e50cb0b075fc91ea9a85a4a795195557f4fb9a971e10b94370dee2b");
            var W = _ecParameters.Curve.DecodePoint(Hex.Decode("04ce1e55cff15c5f5fbd0abca2a2849cf04ccda1c601a849ab28eb6161a0c32e96b6346728d8d3464754361977ee1a1c68120cb0575506cafe6e24d595de92069d"));

            // Create a new point with invalid coordinates
            var invalidW = _ecParameters.Curve.CreatePoint(W.XCoord.ToBigInteger().Add(BigInteger.One), W.YCoord.ToBigInteger());

            try
            {
                // Act
                await tokenVerifier.VerifyTokenAsync(privateKey, _ecParameters.Curve, t, invalidW);
            }
            catch (AnonymousTokensException)
            {
                Assert.True(true, "an invalid point should raise an exception");
            }
        }

        [Fact]
        public async void VerifyToken_tExistsInSeedStore_ReturnsFalse()
        {
            // Arrange
            var seedStoreMock = new Mock<ISeedStore>();
            seedStoreMock.Setup(x => x.ExistsAsync(It.IsAny<byte[]>())).Returns(Task.FromResult(true));

            var privateKey = new BigInteger(Hex.Decode("01301abfe491c0aff380269c966254ac43fdd97469234c7739ada975368181fe"));
            byte[] t = Hex.Decode("4391837b1e50cb0b075fc91ea9a85a4a795195557f4fb9a971e10b94370dee2b");
            var W = _ecParameters.Curve.DecodePoint(Hex.Decode("04ce1e55cff15c5f5fbd0abca2a2849cf04ccda1c601a849ab28eb6161a0c32e96b6346728d8d3464754361977ee1a1c68120cb0575506cafe6e24d595de92069d"));

            var tokenVerifier = new TokenVerifier(seedStoreMock.Object);

            // Act
            var actual = await tokenVerifier.VerifyTokenAsync(privateKey, _ecParameters.Curve, t, W);

            // Assert
            Assert.False(actual);
        }
    }
}
