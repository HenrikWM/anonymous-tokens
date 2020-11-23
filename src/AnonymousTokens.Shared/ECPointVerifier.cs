using Org.BouncyCastle.Math.EC;

namespace AnonymousTokens.Shared
{
    public static class ECPointVerifier
    {
        /// <summary>
        /// Verifies that a point is valid, on the correct curve and in the corect subgroup.
        /// </summary>
        /// <param name="point">Elliptic curve point that we want to verify</param>
        /// <param name="curve">Elliptic curce that we want to verify against</param>
        /// <returns>True if the point is valid and otherwise false</returns>
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
