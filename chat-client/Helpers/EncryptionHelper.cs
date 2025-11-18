/// <file>EncryptionHelper.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 18th, 2025</date>

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
    /// • Generates one 2048-bit RSA key pair at startup.
    /// • Publishes the public key as DER (PKCS#1 RSAPublicKey) for the handshake.
    /// • Retains the private key locally for decryption; never transmits private material.
    /// • Uses RSA-OAEP with SHA-256 for padding to provide semantic security.
    /// 
    /// PKCS#1 (simplified):
    /// • Public key: compact DER encoding of modulus + exponent.
    /// • Private key: DER encoding of the full RSA private components required for decryption.
    /// • Intended for RSA-only key interchange when both endpoints agree on the format.
    /// • Use ExportRSAPublicKey / ImportRSAPublicKey for PKCS#1 DER serialization.
    /// </summary>

    public static class EncryptionHelper
    {
        /// <summary>Indicates whether decryption is currently enabled.</summary>
        public static bool IsEncryptionActive { get; private set; }

        /// <summary>Holds the public key as a DER-encoded byte array for key exchange.</summary>
        public static byte[] PublicKeyDer { get; private set; }

        /// <summary>Holds the public key as a DER-encoded PKCS#1 RSAPublicKey byte array.</summary>
        public static byte[] PrivateKeyDer { get; private set; }

        /// <summary>Internal RSA instance that holds the in-memory key pair for the session.</summary>
        private static readonly RSA RsaInstance;

        /// <summary>
        /// Initializes a new 2048-bit RSA key pair, 
        /// exports the public key as DER bytes and the private key as DER bytes,
        /// enables the encryption/decryption pipeline by default
        /// and logs initialization.
        /// </summary>
        static EncryptionHelper()
        {
            // Generates a new 2048-bit RSA key pair
            RsaInstance = RSA.Create(2048);

            // Exports the public key as DER PKCS#1 (RSAPublicKey) so ImportRSAPublicKey can consume it
            PublicKeyDer = RsaInstance.ExportRSAPublicKey();

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
        /// Encrypts a UTF-8 plaintext string using the recipient's RSA public key (DER bytes).
        /// • Convert text to UTF-8 bytes. Initializes plaintext for encryption.
        /// • Import public key from DER bytes. Loads recipient RSA key.
        /// • Encrypt with RSA OAEP-SHA256. Uses secure padding and SHA-256.
        /// • Return raw ciphertext bytes or empty array on failure. Errors are logged via LocalizationManager.GetString and Console.WriteLine.
        /// </summary>
        /// <param name="plainMessage">The plaintext string to encrypt. If null or empty returns empty byte[] and logs error.</param>
        /// <param name="recipientPublicKeyDer">Recipient RSA public key encoded in DER format as raw bytes. If null or empty returns empty byte[] and logs error.</param>
        /// <returns>The ciphertext as a byte array ready to be sent over the wire, or an empty array if encryption failed.</returns>
        public static byte[] EncryptMessageToBytes(string plainMessage, byte[] recipientPublicKeyDer)
        {
            if (string.IsNullOrEmpty(plainMessage))
            {
                Console.WriteLine(LocalizationManager.GetString("ErrorPlainTextEmpty"));
                return Array.Empty<byte>();
            }

            if (recipientPublicKeyDer == null || recipientPublicKeyDer.Length == 0)
            {
                Console.WriteLine(LocalizationManager.GetString("ErrorPublicKeyMissing"));
                return Array.Empty<byte>();
            }

            try
            {
                using var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(recipientPublicKeyDer, out _);

                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainMessage);
                byte[] cipherBytes = rsa.Encrypt(plaintextBytes, RSAEncryptionPadding.OaepSHA256);

                return cipherBytes;
            }
            catch (Exception ex)
            {
                string template = LocalizationManager.GetString("ErrorEncryptionFailed");
                Console.WriteLine(string.Format(template, ex.Message));
                return Array.Empty<byte>();
            }
        }

        /// <summary>
        /// Decrypts RSA-OAEP-SHA256 ciphertext using the local private key.
        /// Returns UTF-8 plaintext or a localized error string on failure.
        /// </summary>
        public static string DecryptMessageFromBytes(byte[] cipherBytes)
        {
            if (!IsEncryptionActive)
            {
                ClientLogger.Log("Decryption requested while disabled; returning raw text.", ClientLogLevel.Warn);
                return cipherBytes == null ? string.Empty : Encoding.UTF8.GetString(cipherBytes);
            }

            if (cipherBytes == null || cipherBytes.Length == 0)
            {
                ClientLogger.Log("DecryptMessageFromBytes: cipherBytes is null or empty.", ClientLogLevel.Warn);
                return LocalizationManager.GetString("ErrorDecryptionFailed");
            }

            try
            {
                using var rsa = RSA.Create();

                // Imports private key from DER-encoded bytes into RSA object.
                rsa.ImportRSAPrivateKey(PrivateKeyDer, out _);

                // Performs RSA decryption with OAEP-SHA256 padding.
                byte[] plainBytes = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"RSA decryption failed: {ex.Message}", ClientLogLevel.Error);
                return LocalizationManager.GetString("ErrorDecryptionFailed");
            }
        }
    }
}
