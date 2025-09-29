/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 29th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System;
using System.Net.Sockets;

namespace chat_server
{
    /// <summary>
    /// Continuously listens for incoming packets from the connected client.
    /// Dispatches each packet to the appropriate handler based on its opcode.
    /// Logs unknown opcodes and handles disconnection gracefully.
    /// </summary>
    public class Client
    {
        /// <summary>Gets or sets the client's display name.</summary>
        public string Username { get; set; }

        /// <summary>Gets or sets the client's unique identifier.</summary>
        public Guid UID { get; set; }

        /// <summary>Gets or sets the TCP connection for the client.</summary>
        public TcpClient ClientSocket { get; set; }

        /// <summary>Gets or sets the Base64-encoded RSA public key for encryption.</summary>
        public string? PublicKeyBase64 { get; set; }

        /// <summary>Gets or sets the raw DER bytes of the client's public key.</summary>
        public byte[]? PublicKeyDer { get; set; }

        private readonly PacketReader _packetReader;

        /// <summary>
        /// Initializes a new client instance, creates a PacketReader, and logs startup.
        /// </summary>
        public Client(TcpClient client, string username, Guid uid)
        {
            ClientSocket = client;
            Username = username;
            UID = uid;
            _packetReader = new PacketReader(client.GetStream());

            // Logs that the client is now listening for messages
            Console.WriteLine($"[DEBUG] Listening for messages from {Username}...");
        }

        /// <summary>
        /// Cleans up after a client disconnects: closes the socket,
        /// removes from Program.Users, and broadcasts the event.
        /// </summary>
        private void CleanupAfterDisconnect()
        {
            // Closes the client socket
            try
            {
                ClientSocket.Close();
            }
            catch
            {
                // Swallows any exception on close
            }

            // Broadcasts the disconnection to remaining clients
            Program.BroadcastDisconnect(UID.ToString());

            // Removes this client from the global user list
            if (Program.Users.Remove(this))
            {
                Console.WriteLine($"[DEBUG] Removed user {Username} ({UID}) from user list");
            }
        }

        /// <summary>
        /// Handles opcode 5 by reading sender and recipient UIDs and the message content,
        /// then delegates to Program.BroadcastMessage for routing.
        /// </summary>
        private void HandleChatMessage()
        {
            // Reads the sender UID (16 bytes) and returns a Guid
            Guid senderUid = _packetReader.ReadUid();

            // Reads the recipient UID (16 bytes); treats Guid.Empty as null
            Guid rawRecipient = _packetReader.ReadUid();
            Guid? recipientUid = rawRecipient == Guid.Empty
                ? (Guid?)null
                : rawRecipient;

            // Reads the length-prefixed UTF-8 payload as the message text
            string content = _packetReader.ReadString();

            // Routes the chat message through the central dispatcher
            Program.BroadcastMessage(content, senderUid, recipientUid);
        }

        /// <summary>
        /// Model D: Processes an incoming public‐key exchange packet (opcode 6).
        /// Reads the sender UID and Base64‐encoded RSA public key from the packet.
        /// Stores the key locally in both Base64 and DER formats,
        /// logs the receipt at debug level,
        /// and forwards the key to other connected clients.
        /// </summary>
        private void HandlePublicKeyExchange()
        {
            // Reads the sender UID (16 bytes) and converts it to Guid
            Guid senderUid = _packetReader.ReadUid();

            // Reads the length‐prefixed UTF‐8 payload as the Base64 public key
            string publicKeyBase64 = _packetReader.ReadString();

            // Stores the Base64 key and decodes it into DER format
            PublicKeyBase64 = publicKeyBase64;
            PublicKeyDer = Convert.FromBase64String(publicKeyBase64);

            // Logs the reception of the public key
            ServerLogger.ServerLog($"Received public key from {senderUid} (length: {publicKeyBase64.Length})",
                ServerLogLevel.Debug);

            // Broadcasts the key to all other connected clients
            Program.BroadcastPublicKeyToOthers(this);
        }

        /// <summary>
        /// Model D: Handles a public‐key sync request (opcode 3).
        /// Reads the requester’s UID, then sends each connected user’s public key
        /// in PublicKeyResponse packets. Logs each send operation or failure.
        /// </summary>
        private void HandlePublicKeySyncRequest()
        {
            try
            {
                // Reads the requester UID (16 bytes)
                Guid requesterUid = _packetReader.ReadUid();

                ServerLogger.ServerLog($"Public‐key sync requested by UID: {requesterUid}",
                    ServerLogLevel.Debug);

                // Iterates through all known users
                foreach (var user in Program.Users)
                {
                    // Skips users without a public key
                    if (string.IsNullOrWhiteSpace(user.PublicKeyBase64))
                        continue;

                    try
                    {
                        // Builds the PublicKeyResponse packet
                        var packet = new PacketBuilder();
                        packet.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
                        packet.WriteUid(user.UID);
                        packet.WriteString(user.PublicKeyBase64);

                        // Sends the packet back to the requester
                        var bytes = packet.GetPacketBytes();
                        ClientSocket.GetStream().Write(bytes, 0, bytes.Length);

                        ServerLogger.ServerLog($"Sent public key of {user.Username} (UID: {user.UID}) to requester {requesterUid}",
                            ServerLogLevel.Debug);
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.ServerLog($"Failed to send public key of {user.Username} to {requesterUid}: {ex.Message}",
                            ServerLogLevel.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                ServerLogger.ServerLog($"HandlePublicKeySyncRequest failed: {ex.Message}", ServerLogLevel.Error);
            }
        }


        /// <summary>
        /// Continuously listens for incoming packets from the connected client.
        /// Uses a classic switch statement for clarity and beginner-friendly readability.
        /// Each case matches a named opcode from the ClientPacketOpcode enum.
        /// </summary>
        internal void ListenForMessages()
        {
            while (true)
            {
                try
                {
                    // Reads a single byte and casts it to the packet opcode enum
                    ServerPacketOpCode opcode = (ServerPacketOpCode)_packetReader.ReadByte();

                    switch (opcode)
                    {
                        case ServerPacketOpCode.PublicKeyRequest:
                            HandlePublicKeySyncRequest();
                            break;

                        case ServerPacketOpCode.PlainMessage:
                            HandleChatMessage();
                            break;

                        case ServerPacketOpCode.PublicKeyResponse:
                            HandlePublicKeyExchange();
                            break;

                        default:
                            // Logs unsupported or unknown opcode values
                            Console.WriteLine($"[ERROR] Unknown opcode from {Username}: {opcode}");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    // Logs the disconnection event and performs cleanup
                    Console.WriteLine($"[INFO] Client disconnected: {Username} — {ex.Message}");
                    CleanupAfterDisconnect();
                    break;
                }
            }
        }
    }
}
