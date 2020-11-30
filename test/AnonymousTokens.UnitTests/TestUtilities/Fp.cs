using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;


namespace AnonymousTokens.UnitTests.TestUtilities
{
    /// <summary>
    /// Test-class from ECPointTest.cs in Org.BouncyCastle.Math.EC.Tests
    /// </summary>
    public class Fp
    {
        internal static readonly BigInteger q = new BigInteger("29");

        internal static readonly BigInteger a = new BigInteger("4");

        internal static readonly BigInteger b = new BigInteger("20");

        internal static readonly BigInteger n = new BigInteger("38");

        internal static readonly BigInteger h = new BigInteger("1");

        internal static readonly ECCurve curve = new FpCurve(q, a, b, n, h);

        internal static readonly ECPoint infinity = curve.Infinity;

        internal static readonly int[] pointSource = { 5, 22, 16, 27, 13, 6, 14, 6 };

        internal static ECPoint[] p = new ECPoint[pointSource.Length / 2];

        /**
         * Creates the points on the curve with literature values.
         */
        internal static void CreatePoints()
        {
            for (int i = 0; i < pointSource.Length / 2; i++)
            {
                p[i] = curve.CreatePoint(
                    new BigInteger(pointSource[2 * i].ToString()),
                    new BigInteger(pointSource[2 * i + 1].ToString()));
            }
        }
    }
}
