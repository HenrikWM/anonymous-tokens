using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace AnonymousTokensConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            var strength = 256;

            // Generate private key k,
            // and public key K.
            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(new KeyGenerationParameters(new SecureRandom(), strength));
            var keyPair = generator.GenerateKeyPair();

            // Generate token Q = k*P, and create
            // proof (c,z) of correctness, given G and K.
            // TODO

            // Randomise the token Q, by removing
            // the mask r: W = (1/r)*Q = k*P.
            // Also checks that proof (c,z) is correct.
            // TODO

            // Verify that the token (t,W) is correct.
            // TODO            
        }
    }
}
