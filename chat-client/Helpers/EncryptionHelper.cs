/// <file>EncryptionHelper.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 20th, 2025</date>

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

using System.Diagnostics;
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
        /// Clears the currently loaded RSA private key from memory.
        /// Used when encryption is disabled or reset, to prevent unintended decryption attempts.
        /// Ensures that the EncryptionHelper is in a clean state and avoids residual cryptographic access.
        /// </summary>
        public static void ClearPrivateKey()
        {
            // Overwrites the private key parameters with empty/default values
            privateKey = new RSAParameters
            {
                Modulus = null,
                Exponent = null,
                D = null,
                P = null,
                Q = null,
                DP = null,
                DQ = null,
                InverseQ = null
            };

            // Logs the reset for debugging purposes
            Debug.WriteLine("[INFO] RSA private key cleared from EncryptionHelper.");
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
        /// Uses OAEP padding with SHA-256 to match the encryption scheme.
        /// Ensures graceful failure handling by catching exceptions and returning a localized fallback string.
        /// </summary>
        /// <param name="encryptedMessage">Base64-encoded string representing the encrypted message.</param>
        /// <returns>Decrypted plain text string if successful; otherwise, a localized error message.</returns>
        public static string DecryptMessage(string encryptedMessage)
        {
            try
            {
                // Creates a new RSA instance and imports the private key
                using var rsa = RSA.Create();
                rsa.ImportParameters(privateKey);

                // Decodes the encrypted message from Base64
                var data = Convert.FromBase64String(encryptedMessage);

                // Decrypts the byte array using OAEP padding with SHA-256
                var decrypted = rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);

                // Converts the decrypted byte array back to a UTF-8 string
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                // Logs the error for debugging purposes
                Console.WriteLine($"[ERROR] RSA decryption failed: {ex.Message}");

                // Returns a localized fallback message to avoid crashing the UI
                return LocalizationManager.GetString("DecryptionFailed");
            }
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

        /// <summary>
        /// Checks whether the RSA private key has been successfully initialized.
        /// Used to validate decryption readiness before attempting to decrypt messages.
        /// Prevents runtime errors caused by missing or uninitialized key material.
        /// </summary>
        /// <returns>True if the private key is initialized; otherwise, false.</returns>
        public static bool IsPrivateKeyValid()
        {
            // Checks that essential RSA parameters are present
            return privateKey.Modulus != null &&
                   privateKey.Exponent != null &&
                   privateKey.D != null &&
                   privateKey.P != null &&
                   privateKey.Q != null;
        }

        /// <summary>
        /// Validates that a string is a well-formed Base64-encoded value.
        /// </summary>
        public static bool IsValidBase64(string base64)
        {
            if (string.IsNullOrWhiteSpace(base64))
                return false;

            try
            {
                Convert.FromBase64String(base64);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Sets the RSA private key used for decryption.
        /// Accepts a Base64-encoded XML string and parses it into RSAParameters.
        /// This method must be called before attempting to decrypt any message.
        /// </summary>
        /// <param name="privateKeyBase64">Base64-encoded XML RSA private key.</param>
        public static void SetPrivateKey(string privateKeyBase64)
        {
            // Decode the Base64 string into raw XML text
            var xml = Encoding.UTF8.GetString(Convert.FromBase64String(privateKeyBase64));

            // Create a new RSA instance to parse the XML key
            using var rsa = RSA.Create();

            // Import the XML-formatted RSA key into the RSA instance
            rsa.FromXmlString(xml);

            // Export the parsed key as RSAParameters and store it in the static field
            privateKey = rsa.ExportParameters(true);
        }
    }
}

