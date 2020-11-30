
using AnonymousTokens.UnitTests.TestUtilities;

using Org.BouncyCastle.Asn1.X9;

using Xunit;

namespace AnonymousTokens.UnitTests
{
    public class ECPointVerifierTests
    {
        public ECPointVerifierTests()
        {
            Fp.CreatePoints();
        }

        [Fact]
        public void PointIsValid_PointIsOnCurve_ReturnsTrue()
        {
            // Arrange            
            var curve = Fp.curve;
            var point = Fp.p[0];

            // Act
            var actual = ECPointVerifier.PointIsValid(point, curve);

            // Assert
            Assert.True(actual);
        }

        [Fact]
        public void PointIsValid_PointIsNotOnCurve_ReturnsFalse()
        {
            // Arrange
            var x9 = ECNamedCurveTable.GetByName("prime239v1");
            var curve = x9.Curve;
            var point = Fp.p[0];

            // Act
            var actual = ECPointVerifier.PointIsValid(point, curve);

            // Assert
            Assert.False(actual);
        }
    }
}
