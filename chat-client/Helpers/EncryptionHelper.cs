/// <file>EncryptionHelper.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

///<summary>
///Technical note : 
///  RSA is a widely adopted asymmetric encryption algorithm used in SSL/TLS, 
///  digital signatures, and secure messaging.
///  Its strength lies in the mathematical difficulty of factoring large prime numbers,
///  allowing secure key exchange without sharing secrets.
///                 
///  The implementation uses a 2048-bit key size, which offers strong security while 
///  maintaining reasonable performance for short messages.
///  OAEP padding (Optimal Asymmetric Encryption Padding) introduces randomness, 
///  ensuring that identical inputs produce different ciphertexts and preventing 
///  pattern-based attacks.
/// 
///  All cryptographic operations rely on .NET's built-in RSA class, making the solution
///  portable, secure, and production-ready without external dependencies.</summary>

using ChatClient.Helpers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides RSA-based end-to-end encryption utilities for secure message exchange.  
    /// Generates a 2048-bit RSA key pair at runtime, exposes the public key for distribution,  
    /// and keeps the private key local for decryption.  
    /// Uses OAEP padding with SHA-256 to ensure semantic security and prevent ciphertext patterns. 
    /// </summary>
    public static class EncryptionHelper
    {
        /// <summary>
        /// Indicates whether encryption is currently active.  
        /// This flag is updated when the private key is set or cleared.
        /// </summary>
        public static bool IsEncryptionActive { get; private set; } = false;

        // Stores the RSA key pair used for asymmetric encryption.
        // The public key is shared externally; the private key remains local.
        private static RSAParameters publicKey;
        private static RSAParameters privateKey;

        /// <summary>
        /// Static constructor that generates a new RSA key pair (2048 bits).  
        /// The public key is exported for encryption, while the private key is retained for decryption.  
        /// Keys are generated once at runtime and stored in memory.
        /// </summary>
        static EncryptionHelper()
        {
            using var rsa = RSA.Create(2048);
            publicKey = rsa.ExportParameters(false); // Exports only the public key
            privateKey = rsa.ExportParameters(true); // Exports the full key pair
        }

        /// <summary>
        /// Clears the currently loaded RSA private key from memory.  
        /// Used when encryption is disabled or reset, to prevent unintended decryption attempts.  
        /// Ensures that the helper is in a clean state.
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

            IsEncryptionActive = false;

            // Logs the reset for debugging purposes
            Debug.WriteLine("[INFO] RSA private key cleared from EncryptionHelper.");
        }

        /// <summary>
        /// Encrypts a plain text message using the recipient’s RSA public key.  
        /// Uses OAEP padding with SHA-256 to ensure semantic security.  
        /// Only the holder of the corresponding private key can decrypt the result.
        /// </summary>
        /// <param name="plainMessage">The UTF-8 encoded message to encrypt.</param>
        /// <param name="recipientPublicKeyXmlBase64">Base64-encoded XML public key of the recipient.</param>
        /// <returns>Base64-encoded encrypted string safe for transmission.</returns>
        public static string EncryptMessage(string plainMessage, string recipientPublicKeyXmlBase64)
        {
            using var rsa = RSA.Create();

            // Decodes and imports the recipient’s public key from Base64 XML
            string xmlKey = Encoding.UTF8.GetString(Convert.FromBase64String(recipientPublicKeyXmlBase64));
            rsa.FromXmlString(xmlKey);

            byte[] data = Encoding.UTF8.GetBytes(plainMessage);

            // Encrypts the data using OAEP with SHA-256
            byte[] encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Decrypts a Base64-encoded encrypted message using the RSA private key.  
        /// Uses OAEP padding with SHA-256 to match the encryption scheme.  
        /// Returns a localized fallback string if decryption fails.
        /// </summary>
        /// <param name="encryptedMessage">Base64-encoded string representing the encrypted message.</param>
        /// <returns>Decrypted plain text string if successful; otherwise, a localized error message.</returns>
        public static string DecryptMessage(string encryptedMessage)
        {
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportParameters(privateKey);

                // Decodes the encrypted message from Base64
                byte[] data = Convert.FromBase64String(encryptedMessage);

                // Decrypts the data using OAEP with SHA-256
                byte[] decrypted = rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);

                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"RSA decryption failed: {ex.Message}", LogLevel.Error);
                return LocalizationManager.GetString("DecryptionFailed");
            }
        }

        /// <summary>
        /// Returns the RSA public key as a Base64-encoded XML string.  
        /// This can be transmitted to the server or other clients for encryption purposes.
        /// </summary>
        public static string GetPublicKeyBase64()
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(publicKey);

            // Exports the public key as XML
            string xmlKey = rsa.ToXmlString(false);

            // Encodes the XML string in Base64 for safe transmission
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(xmlKey));
        }

        /// <summary>
        /// Checks whether the RSA private key has been successfully initialized.  
        /// Prevents runtime errors caused by missing or uninitialized key material.
        /// </summary>
        public static bool IsPrivateKeyValid()
        {
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
        /// Must be called before attempting to decrypt any message.
        /// </summary>
        public static void SetPrivateKey(string privateKeyBase64)
        {
            // Decodes the Base64 string into raw XML text
            string xml = Encoding.UTF8.GetString(Convert.FromBase64String(privateKeyBase64));

            using var rsa = RSA.Create();

            // Imports the XML-formatted RSA key
            rsa.FromXmlString(xml);

            // Exports the parsed key as RSAParameters and stores it
            privateKey = rsa.ExportParameters(true);

            IsEncryptionActive = true;
        }
    }
}

