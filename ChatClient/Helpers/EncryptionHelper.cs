/// <file>EncryptionHelper.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 10th, 2026</date>

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

namespace ChatClient.Helpers
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
        /// <summary>Holds the public key as a DER-encoded byte array for key exchange.</summary>
        public static byte[] PublicKeyDer { get; private set; }

        /// <summary>Holds the public key as a DER-encoded PKCS#1 RSAPublicKey byte array.</summary>
        public static byte[] PrivateKeyDer { get; private set; }

        /// <summary>Internal RSA instance that holds the in-memory key pair for the session.</summary>
        private static readonly RSA RsaInstance;

        /// <summary>
        /// Initializes a new 2048-bit RSA key pair,
        /// exports the public key as DER bytes and the private key as DER bytes,
        /// enables the encryption/decryption pipeline by default,
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

            // Proper logging via ClientLogger instead of Debug.WriteLine
            ClientLogger.Log("EncryptionHelper initialized with RSA 2048 key pair.", ClientLogLevel.Info);
        }

        /// <summary>
        /// Disables decryption by clearing the local private key reference.
        /// </summary>
        public static void ClearLocalPrivateKey()
        {
            Debug.WriteLine("[INFO] EncryptionHelper decryption disabled.");
        }

        /// <summary>
        /// Decrypts RSA-OAEP-SHA256 ciphertext using the provided private key.
        /// Returns UTF-8 plaintext or a localized error string on failure.
        /// </summary>
        public static string DecryptMessageFromBytes(byte[] cipherBytes, byte[] privateKeyDer)
        {
            if (cipherBytes == null || cipherBytes.Length == 0)
            {
                ClientLogger.Log("DecryptMessageFromBytes: cipherBytes is null or empty.", ClientLogLevel.Warn);
                return LocalizationManager.GetString("ErrorDecryptionFailed");
            }

            try
            {
                /// <summary> Creates an RSA instance for decryption. </summary>
                using var rsa = RSA.Create();

                /// <summary> Imports private key from DER-encoded bytes into RSA object. </summary>
                rsa.ImportRSAPrivateKey(privateKeyDer, out _);

                /// <summary> Performs RSA decryption of cipherBytes using OAEP-SHA256 padding. </summary>
                byte[] plainBytes = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);

                /// <summary> Converts decrypted byte array to UTF-8 string and returns it. </summary>
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                /// <summary> Logs decryption failure and returns a localized error placeholder. </summary>
                ClientLogger.Log($"RSA decryption failed: {ex.Message}", ClientLogLevel.Error);
                return LocalizationManager.GetString("ErrorDecryptionFailed");
            }
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
                /// <summary> Creates a new RSA instance for encryption. </summary>
                using var rsa = RSA.Create();

                /// <summary> Imports recipient's public key in DER format into the RSA instance. </summary>
                rsa.ImportRSAPublicKey(recipientPublicKeyDer, out _);

                /// <summary> Converts plaintext string into UTF-8 encoded byte array. </summary>
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainMessage);

                /// <summary> Encrypts plaintext bytes with recipient's public key using OAEP-SHA256 padding. </summary>
                byte[] cipherBytes = rsa.Encrypt(plaintextBytes, RSAEncryptionPadding.OaepSHA256);

                /// <summary> Returns encrypted byte array to caller. </summary>
                return cipherBytes;
            }

            catch (Exception ex)
            {
                string template = LocalizationManager.GetString("ErrorEncryptionFailed");
                Console.WriteLine(string.Format(template, ex.Message));
                return Array.Empty<byte>();
            }
        }
    }
}
