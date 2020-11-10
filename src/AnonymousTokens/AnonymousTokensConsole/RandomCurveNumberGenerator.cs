using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace AnonymousTokensConsole
{
    public class RandomCurveNumberGenerator
    {
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
