using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using System;
using System.Linq;
using System.Text;

namespace AnonymousTokensConsole
{
    class Program
    {
        static string ToHex(byte[] data) => string.Concat(data.Select(x => x.ToString("x2")));

        static void Main(string[] args)
        {
            var strength = 256;

            // Generate private key k,
            // and public key K.
            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(new KeyGenerationParameters(new SecureRandom(), strength));
            var keyPair = generator.GenerateKeyPair();

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            Console.WriteLine($"Private key: {ToHex(privateKey.D.ToByteArrayUnsigned())}");
            Console.WriteLine($"Public key: {ToHex(publicKey.Q.GetEncoded())}");

            // Generate token Q = k*P, and create
            // proof (c,z) of correctness, given G and K.
            // TODO

            // Randomise the token Q, by removing
            // the mask r: W = (1/r)*Q = k*P.
            // Also checks that proof (c,z) is correct.
            // TODO

            // Verify that the token (t,W) is correct.
            // TODO            

            var payload = "Hello world";

            var signature = GetSignature(payload, keyPair.Private);

            Console.WriteLine($"Signature: {signature}");

            if (VerifySignature(keyPair.Public, signature, payload))
            {
                Console.WriteLine("Valid signature!");
            }
            else
            {
                Console.WriteLine("Invalid signature.");
            }
        }

        private static string GetSignature(string payload, AsymmetricKeyParameter key)
        {
            try
            {
                byte[] msgBytes = Encoding.UTF8.GetBytes(payload);

                ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                signer.Init(true, key);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                byte[] sigBytes = signer.GenerateSignature();

                return Convert.ToBase64String(sigBytes);
            }
            catch (Exception exception)
            {
                Console.WriteLine("Signing failed: " + exception.ToString());
                return null;
            }
        }

        private static bool VerifySignature(AsymmetricKeyParameter key, string signature, string payload)
        {
            try
            {
                byte[] msgBytes = Encoding.UTF8.GetBytes(payload);
                byte[] sigBytes = Convert.FromBase64String(signature);

                ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                signer.Init(false, key);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                return signer.VerifySignature(sigBytes);
            }
            catch (Exception exception)
            {
                Console.WriteLine("Verification failed with the error: " + exception.ToString());
                return false;
            }
        }
    }
}
