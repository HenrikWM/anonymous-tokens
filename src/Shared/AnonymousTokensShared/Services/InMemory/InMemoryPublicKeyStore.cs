using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;

namespace AnonymousTokensShared.Services.InMemory
{
    public class InMemoryPublicKeyStore : IPublicKeyStore
    {
        public ECPublicKeyParameters Get()
        {
            BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

            FpCurve curve = new FpCurve(
                new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
                n, BigInteger.One);

            ECDomainParameters parameters = new ECDomainParameters(
                curve,
                curve.DecodePoint(Hex.Decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
                n, BigInteger.One);

            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(
                "EC",
                curve.DecodePoint(Hex.Decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
                parameters);

            return publicKeyParameters;
        }
    }
}
