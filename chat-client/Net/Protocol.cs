/// <file>Protocol.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 23th, 2025</date>

using System;

namespace chat_client.Net
{
    /// <summary>
    /// Defines all opcodes used in the chat protocol.
    /// Includes both client→server and server→client packet types.
    /// </summary>
    public enum ClientPacketOpCode : byte
    {
        /// <summary>
        /// Client handshake packet.
        /// Contains: Username; UserId; PublicKeyBase64.</summary>
        Handshake = 0,

        /// <summary>
        /// Broadcasts the complete roster of all currently connected users.
        /// Payload begins with the total user count, followed by each user’s
        /// UserId, Username, and PublicKeyBase64.
        /// </summary>
        RosterBroadcast = 1,

        /// <summary>
        /// Client requests a peer's public key.
        /// Contains: RequesterUserId; TargetUserId.</summary>
        PublicKeyRequest = 3,

        /// <summary>
        /// Client sends a plain-text chat message.
        /// Contains: SenderUserId; RecipientUserId; MessageText.</summary>
        PlainMessage = 5,

        /// <summary>
        /// Client responds to a key request with its public key.
        /// Contains: ResponderUserId; PublicKeyBase64; RequesterUserId.</summary>
        PublicKeyResponse = 6,

        /// <summary>
        /// Server notifies all clients of a user disconnection.
        /// Contains: DisconnectingUserId.</summary>
        DisconnectNotify = 10,

        /// <summary>
        /// Client sends an encrypted chat message.
        /// Contains: SenderUserId; RecipientUserId; CipherText.</summary>
        EncryptedMessage = 11,

        /// <summary>
        /// Server instructs this client to disconnect.
        /// Contains: TargetUserId.</summary>
        ForceDisconnectClient = 12
    }
}


