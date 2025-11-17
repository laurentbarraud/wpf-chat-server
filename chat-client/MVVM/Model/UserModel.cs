/// <file>UserModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 17th, 2025</date>

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
        /// Initialized to Guid.Empty to satisfy nullable warnings.
        /// </summary>
        public Guid UID { get; set; } = Guid.Empty;

        /// <summary>
        /// RSA public key used for encrypting outbound messages and verifying identity.
        /// Encoded as a DER-formatted byte array and stored locally for session use.
        /// Never transmitted unless explicitly shared during key exchange.
        /// Initialized to an empty array to avoid null handling across the codebase.
        /// </summary>
        public byte[] PublicKeyDer { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// RSA private key used to decrypt incoming messages addressed to the local client.
        /// Stored locally as a DER-encoded byte array and never transmitted over the network.
        /// Initialized to an empty array to avoid null handling across the codebase.
        /// </summary>
        public byte[] PrivateKeyDer { get; set; } = Array.Empty<byte>();
    }
}
