/// <file>UserModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 8th, 2025</date>

using System;

namespace chat_client.MVVM.Model
{
    /// <summary>
    /// Represents a connected user in the chat system.
    /// Includes identity information and optional cryptographic keys for secure communication.
    /// </summary>
    public class UserModel
    {
        /// <summary>
        /// Display name chosen by the user.
        /// Used for identification in the UI and server logs.
        /// Initialized to empty string to satisfy nullable warnings.
        /// </summary>
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Globally unique identifier assigned to the user upon connection.
        /// Used for key exchange and message routing.
        /// Initialized to empty string to satisfy nullable warnings.
        /// </summary>
        public string UID { get; set; } = string.Empty;

        /// <summary>
        /// Base64-encoded XML RSA public key used to encrypt outgoing messages to this user.
        /// Assigned during encryption setup and transmitted to other clients.
        /// Initialized to empty string to satisfy nullable warnings.
        /// </summary>
        public string PublicKeyBase64 { get; set; } = string.Empty;

        /// <summary>
        /// Base64-encoded XML RSA private key used to decrypt incoming messages.
        /// Stored locally and never transmitted.
        /// Initialized to empty string to satisfy nullable warnings.
        /// </summary>
        public string PrivateKeyBase64 { get; set; } = string.Empty;

        /// <summary>
        /// Clears all stored cryptographic keys from the user model.
        /// Called when encryption is disabled or reset to ensure clean state.
        /// Prevents reuse of outdated keys and supports future features like key rotation.
        /// </summary>
        public void ClearEncryption()
        {
            PublicKeyBase64 = string.Empty;
            PrivateKeyBase64 = string.Empty;
        }
    }
}
