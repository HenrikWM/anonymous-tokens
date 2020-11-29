using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;

using Xunit;

namespace AnonymousTokens.UnitTests
{
    public class ECCurveHashTests
    {
        [Theory]
        [InlineData("3342403536405981729393488334694600415596881826869351677613")]
        [InlineData("5735822328888155254683894997897571951568553642892029982342")]
        [InlineData("-15392676890630437317721681665788413720756934076096835125044231120241806601564")]
        public void HashToWeierstrassCurve_tIsNotWithinRangeOfP_ReturnsNull(string randomBigInteger)
        {
            // Arrange
            var x9 = ECNamedCurveTable.GetByName("prime239v1");
            var curve = x9.Curve;
            byte[] t = new BigInteger(randomBigInteger).ToByteArray();

            // Act
            var actual = ECCurveHash.HashToWeierstrassCurve(curve, t);

            // Assert
            Assert.Null(actual);
        }
    }
}
