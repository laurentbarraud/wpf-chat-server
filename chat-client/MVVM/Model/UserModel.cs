/// <file>UserModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 16th, 2025</date>

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Globally unique identifier assigned to the user upon connection.
        /// Used for key exchange and message routing.
        /// </summary>
        public string UID { get; set; }

        /// <summary>
        /// Base64-encoded XML RSA public key used to encrypt outgoing messages to this user.
        /// Assigned during encryption setup and transmitted to other clients.
        /// </summary>
        public string? PublicKeyBase64 { get; set; }

        /// <summary>
        /// Base64-encoded XML RSA private key used to decrypt incoming messages.
        /// Stored locally and never transmitted.
        /// </summary>
        public string? PrivateKeyBase64 { get; set; }

        /// <summary>
        /// Clears all stored cryptographic keys from the user model.
        /// Called when encryption is disabled or reset to ensure clean state.
        /// Prevents reuse of outdated keys and supports future features like key rotation.
        /// </summary>
        public void ClearEncryption()
        {
            PublicKeyBase64 = null;
            PrivateKeyBase64 = null;
        }
    }
}
