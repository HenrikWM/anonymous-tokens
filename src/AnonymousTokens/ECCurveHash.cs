
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

            BigInteger P = curve.Field.Characteristic;
            SHA256? sha256 = SHA256.Create();
            BigInteger hash = new BigInteger(sha256.ComputeHash(t));

            // Check that the hash is within valid range
            if (hash.CompareTo(BigInteger.One) < 0 || hash.CompareTo(P) >= 0)
                return null;

            // A valid point (x,y) must satisfy: y^2 = x^3 + Ax + B mod P
            // Convert hash from BigInt to FieldElement x modulo P
            x = curve.FromBigInteger(hash);         // x
            ax = x.Multiply(curve.A);               // Ax
            x3 = x.Multiply(x).Multiply(x);         // x^3
            y2 = x3.Add(ax).Add(curve.B);           // y^2 = x^3 + Ax + B
            y = y2.Sqrt();                          // y = sqrt(x^3 + Ax + B)

            // y == null if square root mod P does not exist
            if (y == null)
                return null;

            ECPoint T = curve.CreatePoint(x.ToBigInteger(), y.ToBigInteger());

            // Multiply the point with the cofactor. If it becomes the identity, we have
            // been unlucky with our choice of point, and should try again.
            if (T.Multiply(curve.Cofactor).Equals(curve.Infinity))
                return null;

            return T;
        }
    }
}
