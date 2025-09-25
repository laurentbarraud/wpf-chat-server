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
        /// Initializes the EncryptionHelper by creating a single 2048-bit RSA instance.
        /// Exports the public key as Base64-encoded XML for distribution,
        /// and retains the private key XML for all subsequent decryptions.
        /// </summary>
        static EncryptionHelper()
        {
            // Creates and retains one RSA instance for key generation.
            var rsa = RSA.Create(2048);

            // Exports public key to XML, then Base64-encodes it for safe transport.
            string publicXml = rsa.ToXmlString(false);
            PublicKeyXmlBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicXml));

            // Exports private key to XML (never shared externally).
            PrivateKeyXml = rsa.ToXmlString(true);
        }

        // Backing fields in the same class:
        private static readonly string PrivateKeyXml;
        public static readonly string PublicKeyXmlBase64;

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
        /// Decrypts a Base64-encoded OAEP/SHA-256 ciphertext using the local private key XML.
        /// Returns the UTF-8 plaintext or a localized error on failure.
        /// </summary>
        /// <param name="encryptedMessage">The Base64 ciphertext to decrypt.</param>
        /// <returns>The decrypted text, or a fallback message on error.</returns>
        public static string DecryptMessage(string encryptedMessage)
        {
            try
            {
                // Decodes the Base64 into raw cipher bytes.
                byte[] cipherBytes = Convert.FromBase64String(encryptedMessage);

                // Instantiates a fresh RSA context and imports the private key.
                using var rsaDec = RSA.Create();
                rsaDec.FromXmlString(PrivateKeyXml);

                // Decrypts with the same OAEP/SHA-256 padding.
                byte[] plainBytes = rsaDec.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);

                // Returns the UTF-8 string.
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                // Logs the failure and returns a localized fallback.
                ClientLogger.Log($"RSA decryption failed: {ex.Message}", LogLevel.Error);
                return LocalizationManager.GetString("DecryptionFailed");
            }
        }

        /// <summary>
        /// Encrypts the given plaintext with the recipient’s public key XML.
        /// Uses OAEP with SHA-256 padding to ensure semantic security.
        /// </summary>
        /// <param name="plainMessage">The UTF-8 text to encrypt.</param>
        /// <param name="recipientPublicKeyXmlBase64">
        ///   The Base64-encoded XML public key of the recipient.
        /// </param>
        /// <returns>
        ///   A Base64-encoded ciphertext safe for network transmission.
        /// </returns>
        public static string EncryptMessage(string plainMessage, string recipientPublicKeyXmlBase64)
        {
            // Instantiates a fresh RSA context for encryption.
            using var rsaEnc = RSA.Create();

            // Imports recipient’s public key from Base64-encoded XML.
            string recipientXml = Encoding.UTF8.GetString(Convert.FromBase64String(recipientPublicKeyXmlBase64));
            rsaEnc.FromXmlString(recipientXml);

            // Encrypts the UTF-8 bytes with OAEP/SHA-256 padding.
            byte[] cipherBytes = rsaEnc.Encrypt(
                Encoding.UTF8.GetBytes(plainMessage),
                RSAEncryptionPadding.OaepSHA256);

            // Returns the result as Base64 for sending.
            return Convert.ToBase64String(cipherBytes);
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

