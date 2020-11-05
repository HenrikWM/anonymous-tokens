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

            var plainText = "Hello world";

            var signature = SignData(plainText, keyPair.Private);

            Console.WriteLine($"Signature: {signature}");

            if (VerifySignature(keyPair.Public, signature, plainText))
            {
                Console.WriteLine("Valid signature!");
            }
            else
            {
                Console.WriteLine("Invalid signature.");
            }
        }

        private static string SignData(string msg, AsymmetricKeyParameter privKey)
        {
            try
            {
                byte[] msgBytes = Encoding.UTF8.GetBytes(msg);

                ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                signer.Init(true, privKey);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                byte[] sigBytes = signer.GenerateSignature();

                return Convert.ToBase64String(sigBytes);
            }
            catch (Exception exc)
            {
                Console.WriteLine("Signing Failed: " + exc.ToString());
                return null;
            }
        }

        private static bool VerifySignature(AsymmetricKeyParameter pubKey, string signature, string msg)
        {
            try
            {
                byte[] msgBytes = Encoding.UTF8.GetBytes(msg);
                byte[] sigBytes = Convert.FromBase64String(signature);

                ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                signer.Init(false, pubKey);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                return signer.VerifySignature(sigBytes);
            }
            catch (Exception exc)
            {
                Console.WriteLine("Verification failed with the error: " + exc.ToString());
                return false;
            }
        }
    }
}
