/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

using chat_server.Net.IO;
using chat_server.Helpers;
using System.Net.Sockets;

namespace chat_server
{
    /// <summary>
    /// Represents a connected client on the server side.
    /// Stores identity information including Username, UID, and RSA public key.
    /// Manages the TCP socket and packet reader for incoming communication.
    /// Continuously listens for packets and dispatches logic based on opcode values.
    /// </summary>
    public class Client
    {
        /// <summary>
        /// The display name of the connected user.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// The unique identifier assigned to the client.
        /// </summary>
        public Guid UID { get; set; }

        /// <summary>
        /// The TCP socket used for communication with the client.
        /// </summary>
        public TcpClient ClientSocket { get; set; }


        /// <summary>
        /// The packet reader used to parse incoming data from the client.
        /// </summary>
        private readonly PacketReader _packetReader;

        /// <summary>
        /// Stores the client's public RSA key in Base64 format for encryption distribution.
        /// Populated during handshake or key exchange.
        /// </summary>
        public string PublicKeyBase64 { get; set; }

        /// <summary>
        /// Initializes a new client instance with the provided TCP socket, username, and UID.
        /// Instantiates the packet reader and prepares the client for message listening.
        /// </summary>
        /// <param name="client">The accepted TCP client socket.</param>
        /// <param name="username">The display name of the connected user.</param>
        /// <param name="uid">The unique identifier assigned by the client.</param>
        public Client(TcpClient client, string username, Guid uid)
        {
            ClientSocket = client;
            Username = username;
            UID = uid; // Uses the UID provided by the client

            _packetReader = new PacketReader(ClientSocket.GetStream());

            ServerLogger.Log($"Listening for messages from {Username}...", LogLevel.Debug);
        }      

        /// <summary>
        /// Continuously listens for incoming packets from the connected client.
        /// Logic is based on opcode values and routes each packet to its corresponding handler.
        /// Ensures protocol alignment by reading expected fields in correct order.
        /// Terminates the loop and triggers disconnect broadcast if an exception occurs.
        /// This method is central to the server's real-time message routing and encryption key exchange.
        /// </summary>
        internal void ListenForMessages()
        {
            while (true)
            {
                try
                {
                    // Reads the next opcode from the stream — defines packet type
                    var opcode = _packetReader.ReadByte();

                    switch (opcode)
                    {
                        case 3: // Public key sync request
                            string requesterUid = _packetReader.ReadMessage();
                            ServerLogger.Log($"Public key sync requested by UID: {requesterUid}", LogLevel.Debug);

                            foreach (var user in Program._users)
                            {
                                if (string.IsNullOrEmpty(user.PublicKeyBase64))
                                    continue;

                                try
                                {
                                    var responsePacket = new PacketBuilder();
                                    responsePacket.WriteOpCode(6); // Public key exchange
                                    responsePacket.WriteMessage(user.UID.ToString());
                                    responsePacket.WriteMessage(user.PublicKeyBase64);

                                    ClientSocket.GetStream().Write(
                                        responsePacket.GetPacketBytes(),
                                        0,
                                        responsePacket.GetPacketBytes().Length
                                    );

                                    ServerLogger.Log($"Sent public key of {user.Username} to {Username}", LogLevel.Debug);
                                }
                                catch (Exception ex)
                                {
                                    ServerLogger.Log($"Failed to send key to {Username}: {ex.Message}", LogLevel.Error);
                                }
                            }

                            break;

                        case 5: // Public (or routed) chat message
                                // Extracts in order: sender UID, recipient UID (empty = broadcast), then content
                            string senderStr = _packetReader.ReadMessage();
                            string recipientStr = _packetReader.ReadMessage();
                            string content = _packetReader.ReadMessage();

                            Guid senderGuid = Guid.Parse(senderStr);
                            Guid? recipientGuid = string.IsNullOrEmpty(recipientStr)
                                                    ? (Guid?)null
                                                    : Guid.Parse(recipientStr);

                            // Uses the unified BroadcastMessageToAll method
                            Program.BroadcastMessage(content, senderGuid, recipientGuid);
                            break;

                        case 6: // Public key exchange
                                // Reads sender UID and public RSA key
                            string senderUidForKey = _packetReader.ReadMessage();
                            string publicKeyBase64 = _packetReader.ReadMessage();

                            // Stores the key locally and triggers broadcast to other clients
                            this.PublicKeyBase64 = publicKeyBase64;
                            ServerLogger.Log($"Public key received from {Username} — UID: {senderUidForKey}, Length: {publicKeyBase64.Length}", LogLevel.Debug);
                            Program.BroadcastPublicKeyToOthers(this);
                            break;

                        default:
                            // Logs unknown opcodes for debugging and protocol validation
                            ServerLogger.Log($"Unknown opcode received from {Username}: {opcode}", LogLevel.Error);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    // Handles disconnection or stream failure gracefully
                    ServerLogger.Log($"[{DateTime.Now}]: {LocalizationManager.GetString("ClientDisconnected")} {Username}", LogLevel.Info);
                    ClientSocket.Close();
                    Program.BroadcastDisconnect(UID.ToString());

                    // Remove the disconnected client from the global list.
                    // This prevents reconnection issues if the same user (same pseudo) returns with a new UID
                    // It also ensures the server doesn't retain stale references to closed sockets
                    Program._users.Remove(this);
                    ServerLogger.Log($"User removed from list of users — {this.Username} ({UID.ToString()})", LogLevel.Debug);

                    break;
                }
            }
        }
    }
}
