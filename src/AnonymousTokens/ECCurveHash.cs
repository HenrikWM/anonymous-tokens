
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

using System.Security.Cryptography;

using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace AnonymousTokens
{
    public static class ECCurveHash
    {
        /// <summary>
        /// Hashes a seed t into a point T on the curve. Returns null if t is unsuitable.
        /// </summary>
        /// <param name="curve">The elliptic curve in Weierstrass form</param>
        /// <param name="t">The seed</param>
        /// <returns>A random point T uniquely determined by seed t, otherwise null</returns>
        public static ECPoint? HashToWeierstrassCurve(ECCurve curve, byte[] t)
        {
            ECFieldElement x, ax, x3, y, y2;

            var P = curve.Field.Characteristic;
            var sha256 = SHA256.Create();
            var hashAsInt = new BigInteger(sha256.ComputeHash(t));

            // Check that the hash is within valid range
            if (hashAsInt.CompareTo(BigInteger.One) < 0 || hashAsInt.CompareTo(P) >= 0)
                return null;

            // A valid point (x,y) must satisfy: y^2 = x^3 + Ax + B mod P
            // Convert hash from BigInt to FieldElement x modulo P
            x = curve.FromBigInteger(hashAsInt);    // x
            ax = x.Multiply(curve.A);               // Ax
            x3 = x.Square().Multiply(x);            // x^3 = x^2 * x
            y2 = x3.Add(ax).Add(curve.B);           // y^2 = x^3 + Ax + B
            y = y2.Sqrt();                          // y = sqrt(x^3 + Ax + B)

            // y == null if square root mod P does not exist
            if (y == null)
                return null;

            ECPoint T = curve.CreatePoint(x.ToBigInteger(), y.ToBigInteger());

            // Use the built-in point validator, which also checks for membership
            // in weak subgroups
            if (!T.IsValid())
                return null;

            return T;
        }
    }
}
