using Org.BouncyCastle.Math.EC;

namespace AnonymousTokensShared
{
    public static class ECPointVerifier
    {
        public static bool PointIsValid(ECPoint point, ECCurve curve)
        {
            if (point == null || !curve.Equals(point.Curve) || point.Multiply(curve.Cofactor).Equals(curve.Infinity))
            {
                return false;
            }

            return true;
        }
    }
}
