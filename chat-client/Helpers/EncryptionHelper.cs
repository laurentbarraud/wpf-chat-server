/// <file>EncryptionHelper.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 9th, 2025</date>

using System.Security.Cryptography;
using System.Text;

namespace chat_client.Helpers
{
    public static class EncryptionHelper
    {
        private static RSAParameters publicKey;
        private static RSAParameters privateKey;

        static EncryptionHelper()
        {
            using var rsa = RSA.Create(2048);
            publicKey = rsa.ExportParameters(false);  // Public key only
            privateKey = rsa.ExportParameters(true);  // Full key pair
        }

        /// <summary>
        /// Encrypts a plain text message using the public key.
        /// </summary>
        public static string EncryptMessage(string plainMessage)
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(publicKey);

            var data = Encoding.UTF8.GetBytes(plainMessage);
            var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

            // Convert to Base64 to ensure safe transmission over text-based protocols
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Decrypts a Base64-encoded encrypted message using the private key.
        /// </summary>
        public static string DecryptMessage(string encryptedMessage)
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(privateKey);

            var data = Convert.FromBase64String(encryptedMessage);
            var decrypted = rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// Returns the public key in Base64 format for transmission to the server.
        /// </summary>
        public static string GetPublicKeyBase64()
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(publicKey);

            // Export public key as XML string
            string xmlKey = rsa.ToXmlString(false);

            // Convert to Base64 to ensure safe transmission
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(xmlKey));
        }
    }
}
