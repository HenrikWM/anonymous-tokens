using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AnonymousTokensShared
{

    public class InMemoryKeyPairGenerator : IKeyPairGenerator
    {
        /// <summary>
        /// Generate private key k and public key K.
        /// </summary>
        /// <param name="ecParameters">The Elliptic Curve X9ECParameters-parameters with the curve, points etc.</param>
        /// <returns>The key pair with private and public key</returns>
        public AsymmetricCipherKeyPair CreateKeyPair(X9ECParameters ecParameters)
        {
            var generator = new ECKeyPairGenerator("EC");

            var domainParams = new ECDomainParameters(ecParameters.Curve, ecParameters.G, ecParameters.N, ecParameters.H, ecParameters.GetSeed());
            var random = new SecureRandom();

            var keyGenerationParameters = new ECKeyGenerationParameters(domainParams, random);

            generator.Init(keyGenerationParameters);

            return generator.GenerateKeyPair();
        }
    }
}
