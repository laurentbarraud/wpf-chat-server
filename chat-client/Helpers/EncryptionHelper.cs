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
        /// Initializes the EncryptionHelper by generating a fresh 2048-bit RSA key pair.
        /// Exports the public key parameters for external encryption and retains the
        /// private key parameters for internal decryption.
        /// </summary>
        static EncryptionHelper()
        {
            // Creates a new RSA instance with a 2048-bit key size.
            using var rsa = RSA.Create(2048);

            // Exports only the public key components for use by other clients.
            publicKey = rsa.ExportParameters(false);

            // Exports the complete key pair (public + private) for local decryption.
            privateKey = rsa.ExportParameters(true);
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
        /// Encrypts the specified plaintext message using the recipient’s RSA public key.
        /// Uses OAEP with SHA-256 padding to guarantee semantic security.
        /// </summary>
        /// <param name="plainMessage">The UTF-8 encoded plaintext to encrypt.</param>
        /// <param name="recipientPublicKeyXmlBase64">
        ///   The Base64-encoded XML representation of the recipient’s RSA public key.
        /// </param>
        /// <returns>
        ///   A Base64-encoded ciphertext string safe for transmission.
        /// </returns>
        public static string EncryptMessage(string plainMessage, string recipientPublicKeyXmlBase64)
        {
            // Instantiates a new RSA context for encryption operations.
            using var rsa = RSA.Create();

            // Decodes the Base64 XML and converts it to a UTF-8 string.
            byte[] xmlBytes = Convert.FromBase64String(recipientPublicKeyXmlBase64);
            string xmlKey = Encoding.UTF8.GetString(xmlBytes);

            // Imports the public key parameters into the RSA instance.
            rsa.FromXmlString(xmlKey);

            // Encodes the plaintext message into a byte array.
            byte[] dataBytes = Encoding.UTF8.GetBytes(plainMessage);

            // Encrypts the data using OAEP SHA-256 padding.
            byte[] encryptedBytes = rsa.Encrypt(dataBytes, RSAEncryptionPadding.OaepSHA256);

            // Returns the encrypted bytes as a Base64 string.
            return Convert.ToBase64String(encryptedBytes);
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

