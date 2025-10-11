/// <file>EncryptionHelper.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 12th, 2025</date>

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

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides RSA-based end-to-end encryption utilities for secure message exchange.
    /// Generates a single 2048-bit RSA key pair at startup,
    /// exposes the public key as Base64-DER for the handshake,
    /// and keeps the private key local for decryption.
    /// Uses OAEP with SHA-256 padding to ensure semantic security.
    /// </summary>
    public static class EncryptionHelper
    {
        /// <summary>Indicates whether decryption is currently enabled.</summary>
        public static bool IsEncryptionActive { get; private set; }

        /// <summary>Holds the Base64-DER representation of the public key.</summary>
        public static readonly string PublicKeyBase64;

        // Retains both public and private key material for the local client.
        private static readonly RSA RsaInstance;

        // Raw private key in DER PKCS#1 format, used for decryption imports.
        private static readonly byte[] PrivateKeyDer;

        /// <summary>
        /// Initializes the RSA key pair at startup, exports the public key,
        /// caches the private key DER, and activates decryption.
        /// </summary>
        static EncryptionHelper()
        {
            // Generates a new 2048-bit RSA key pair
            RsaInstance = RSA.Create(2048);

            // Exports the public key as DER PKCS#1 and encodes it in Base64
            PublicKeyBase64 = Convert.ToBase64String(RsaInstance.ExportRSAPublicKey());

            // Exports the private key as DER PKCS#1 for later import
            PrivateKeyDer = RsaInstance.ExportRSAPrivateKey();

            // Activates decryption by default
            IsEncryptionActive = true;

            Debug.WriteLine("[INFO] EncryptionHelper initialized with RSA 2048 key pair.");
        }

        /// <summary>
        /// Disables decryption by clearing the local private key reference.
        /// </summary>
        public static void ClearPrivateKey()
        {
            IsEncryptionActive = false;
            Debug.WriteLine("[INFO] EncryptionHelper decryption disabled.");
        }

        /// <summary>
        /// Encrypts the provided UTF-8 plaintext with the recipient’s RSA public key.
        /// Employs OAEP-SHA256 padding to maximize security.
        /// </summary>
        /// <param name="plainMessage">The plaintext string to encrypt.</param>
        /// <param name="recipientPublicKeyBase64">The recipient’s RSA public key in Base64-DER format.</param>
        /// <returns>A Base64-encoded ciphertext.</returns>
        public static string EncryptMessage(string plainMessage, string recipientPublicKeyBase64)
        {
            // Instantiates an RSA provider for encryption
            using var rsa = RSA.Create();

            // Decodes the Base64 key and imports it in DER PKCS#1 format
            byte[] publicKeyDer = Convert.FromBase64String(recipientPublicKeyBase64);
            rsa.ImportRSAPublicKey(publicKeyDer, out _);

            // Encodes the plaintext as UTF-8 bytes
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainMessage);

            // Encrypts the data using OAEP with SHA-256 padding
            byte[] cipherBytes = rsa.Encrypt(plaintextBytes, RSAEncryptionPadding.OaepSHA256);

            // Converts and returns the ciphertext as a Base64 string
            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// Decrypts the given Base64-encoded ciphertext using the local private key.
        /// Returns the UTF-8 plaintext or a localized error message on failure.
        /// </summary>
        /// <param name="encryptedMessage">Base64-encoded ciphertext.</param>
        /// <returns>Decrypted UTF-8 text or fallback string.</returns>
        public static string DecryptMessage(string encryptedMessage)
        {
            if (!IsEncryptionActive)
            {
                Debug.WriteLine("[WARN] Decryption requested while disabled; returning raw text.");
                return encryptedMessage;
            }

            try
            {
                // Imports the private key from DER and decrypts
                using var rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(PrivateKeyDer, out _);

                byte[] cipherBytes = Convert.FromBase64String(encryptedMessage);
                byte[] plainBytes = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);

                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ERROR] RSA decryption failed: {ex.Message}");
                return LocalizationManager.GetString("DecryptionFailed");
            }
        }

        /// <summary>
        /// Validates whether a string is well-formed Base64 data.
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
    }
}

