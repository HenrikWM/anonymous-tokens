using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace AnonymousTokens.Shared
{
    public static class ECCurveRandomNumberGenerator
    {
        /// <summary>
        /// Generate a random number r such that 0 < r < curve.Order
        /// </summary>
        /// <param name="curve">Curve parameters</param>
        /// <param name="random">Random number generator</param>
        /// <returns>Random number r</returns>
        public static BigInteger GenerateRandomNumber(ECCurve curve, SecureRandom random)
        {
            BigInteger N = curve.Order;
            BigInteger r;

            // Sample random 0 < r < N
            for (; ; )
            {
                r = new BigInteger(N.BitLength, random);
                if (r.CompareTo(BigInteger.One) < 0 || r.CompareTo(N) >= 0)
                    continue;
                break;
            }

            return r;
        }
    }
}
