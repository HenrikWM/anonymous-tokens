using Org.BouncyCastle.Asn1.X9;

using Xunit;

namespace AnonymousTokens.UnitTests
{
    public class ECCurveHashTests
    {
        [Fact]
        public void HashToWeierstrassCurve_tIsNotWithinValidRangeOfP_ReturnsNull()
        {
            // Arrange
            var x9 = ECNamedCurveTable.GetByName("prime239v1");
            var curve = x9.Curve;
            byte[]? t = new byte[32];

            // Act
            var actual = ECCurveHash.HashToWeierstrassCurve(curve, t);

            // Assert
            Assert.Null(actual);
        }
    }
}
