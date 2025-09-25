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
        /// Generates a 2048-bit RSA key pair once at startup.
        /// Exports the public key as DER and encodes it in Base64 for distribution.
        /// Retains the private key DER for all decryptions.
        /// </summary>
        static EncryptionHelper()
        {
            using var rsa = RSA.Create(2048);

            // Export public key in PKCS#1 DER format, then Base64-encode it
            PublicKeyBase64 = Convert.ToBase64String(rsa.ExportRSAPublicKey());

            // Export private key in PKCS#1 DER format (full key)
            PrivateKeyDer = rsa.ExportRSAPrivateKey();
        }

        // Backing fields
        public static readonly string PublicKeyBase64;
        private static readonly byte[] PrivateKeyDer;

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
        /// Decrypts the Base64-encoded OAEP/SHA-256 ciphertext using local private key DER.  
        /// Returns the UTF-8 plaintext or a localized fallback on error.
        /// </summary>
        /// <param name="encryptedMessage">Base64-encoded ciphertext.</param>
        /// <returns>Decrypted UTF-8 string or localized error.</returns>
        public static string DecryptMessage(string encryptedMessage)
        {
            try
            {
                // Creates a temporary RSA instance for decryption
                using var rsa = RSA.Create();

                // Imports the local private key in DER PKCS#1 format
                rsa.ImportRSAPrivateKey(PrivateKeyDer, out _);

                // Decodes and decrypts the ciphertext
                byte[] cipherBytes = Convert.FromBase64String(encryptedMessage);
                byte[] plainBytes = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);

                // Returns the decrypted text
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (FormatException fe)
            {
                // Logs Base64 decoding failures
                ClientLogger.Log($"RSA decryption failed (invalid Base64): {fe.Message}", LogLevel.Error);
                return LocalizationManager.GetString("DecryptionFailed");
            }
            catch (CryptographicException ce)
            {
                // Logs RSA decryption errors
                ClientLogger.Log($"RSA decryption failed (crypto error): {ce.Message}", LogLevel.Error);
                return LocalizationManager.GetString("DecryptionFailed");
            }
            catch (Exception ex)
            {
                // Logs any unexpected decryption error
                ClientLogger.Log($"RSA decryption error: {ex.Message}", LogLevel.Error);
                return LocalizationManager.GetString("DecryptionFailed");
            }
        }

        /// <summary>
        /// Encrypts the UTF-8 plaintext using the recipient’s Base64-DER public key.  
        /// Uses OAEP with SHA-256 padding for semantic security and randomness.
        /// </summary>
        /// <param name="plainMessage">UTF-8 text to encrypt.</param>
        /// <param name="recipientPublicKeyBase64">Base64-encoded DER public key.</param>
        /// <returns>Base64-encoded ciphertext.</returns>
        public static string EncryptMessage(string plainMessage, string recipientPublicKeyBase64)
        {
            // Creates a temporary RSA instance for encryption
            using var rsa = RSA.Create();

            // Imports the recipient's public key in DER PKCS#1 format
            byte[] publicDer = Convert.FromBase64String(recipientPublicKeyBase64);
            rsa.ImportRSAPublicKey(publicDer, out _);

            // Encrypts the UTF-8 bytes with OAEP SHA-256 padding
            byte[] cipher = rsa.Encrypt(
                Encoding.UTF8.GetBytes(plainMessage),
                RSAEncryptionPadding.OaepSHA256);

            // Returns the ciphertext as a Base64 string
            return Convert.ToBase64String(cipher);
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

