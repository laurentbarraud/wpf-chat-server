/// <file>EncryptionHelper.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 12th, 2025</date>

// Technical notes : RSA is a widely adopted asymmetric encryption algorithm used in SSL/TLS, 
//                   digital signatures, and secure messaging.
//                   Its strength lies in the mathematical difficulty of factoring large prime numbers,
//                   allowing secure key exchange without sharing secrets.
//                 
//                   The implementation uses a 2048-bit key size, which offers strong security while 
//                   maintaining reasonable performance for short messages.
//                   OAEP padding (Optimal Asymmetric Encryption Padding) introduces randomness, 
//                   ensuring that identical inputs produce different ciphertexts and preventing 
//                   pattern-based attacks.
// 
//                   All cryptographic operations rely on .NET's built-in RSA class, making the solution
//                   portable, secure, and production-ready without external dependencies.

using System.Security.Cryptography;
using System.Text;

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides RSA-based end-to-end encryption utilities for secure message exchange.
    /// This static helper encapsulates key generation, encryption, and decryption logic.
    ///</summary>
    public static class EncryptionHelper
    {
        // RSA key pair used for asymmetric encryption.
        // Only the public key is shared externally; the private key remains local for decryption.
        private static RSAParameters publicKey;
        private static RSAParameters privateKey;

        /// <summary>
        /// Static constructor that initializes a new RSA key pair (2048 bits).
        /// The public key is used for encryption; the private key is used for decryption.
        /// Keys are generated once at runtime and stored in memory.
        /// </summary>
        static EncryptionHelper()
        {
            using var rsa = RSA.Create(2048); // 2048-bit key size is a widely accepted security standard
            publicKey = rsa.ExportParameters(false);  // Export only the public key (no private exponent)
            privateKey = rsa.ExportParameters(true);  // Export full key pair including private key
        }

        /// <summary>
        /// Encrypts a plain text message using the recipient's RSA public key.
        /// This ensures that only the holder of the corresponding private key can decrypt the message.
        /// </summary>
        /// <param name="plainMessage">The UTF-8 encoded message to encrypt.</param>
        /// <param name="recipientPublicKeyXmlBase64">Base64-encoded XML public key of the recipient.</param>
        /// <returns>Base64-encoded encrypted string safe for transmission over text protocols..</returns>
        public static string EncryptMessage(string plainMessage, string recipientPublicKeyXmlBase64)
        {
            using var rsa = RSA.Create();

            // Decode and import the recipient's public key
            string xmlKey = Encoding.UTF8.GetString(Convert.FromBase64String(recipientPublicKeyXmlBase64));
            rsa.FromXmlString(xmlKey);

            var data = Encoding.UTF8.GetBytes(plainMessage);
            var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

            return Convert.ToBase64String(encrypted);
        }


        /// <summary>
        /// Decrypts a Base64-encoded encrypted message using the RSA private key.
        /// This completes the end-to-end encryption cycle, ensuring only the intended recipient can read the message.
        /// </summary>
        /// <param name="encryptedMessage">Base64-encoded string representing the encrypted message.</param>
        /// <returns>Decrypted plain text string.</returns>
        public static string DecryptMessage(string encryptedMessage)
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(privateKey); // Load the private key into the RSA instance

            var data = Convert.FromBase64String(encryptedMessage); // Decode Base64 to byte array

            // Decrypt using OAEP padding with SHA-256 (must match encryption padding)
            var decrypted = rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);

            return Encoding.UTF8.GetString(decrypted); // Convert decrypted byte array back to UTF-8 string
        }

        /// <summary>
        /// Returns the RSA public key as a Base64-encoded XML string.
        /// This can be transmitted to the server or other clients for encryption purposes.
        /// </summary>
        /// <returns>Base64-encoded XML representation of the public key.</returns>
        public static string GetPublicKeyBase64()
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(publicKey); // Load the public key

            // Export the public key as XML (standard .NET format)
            string xmlKey = rsa.ToXmlString(false);

            // Encode the XML string in Base64 for safe transmission
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(xmlKey));
        }
    }
}

