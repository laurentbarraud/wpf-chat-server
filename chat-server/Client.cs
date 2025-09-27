/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 27th, 2025</date>

using chat_client.Net;
using chat_server.Net;
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
        public string PublicKeyBase64 { get; set; }

        /// <summary>Gets or sets the raw DER bytes of the client's public key.</summary>
        public byte[] PublicKeyDer { get; set; }

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
        /// Handles opcode 5 by reading sender and recipient UIDs and content,
        /// then delegates to Program.BroadcastMessage for routing.
        /// </summary>
        private void HandleChatMessage()
        {
            // Reads the sender UID string
            string senderStr = _packetReader.ReadMessage();

            // Reads the recipient UID or empty
            string recipientStr = _packetReader.ReadMessage();

            // Reads the message content
            string content = _packetReader.ReadMessage();

            // Parses UIDs and invokes broadcast
            Guid senderUid = Guid.Parse(senderStr);
            Guid? recipientUid = string.IsNullOrEmpty(recipientStr) ? (Guid?)null : Guid.Parse(recipientStr);

            Program.BroadcastMessage(content, senderUid, recipientUid);
        }

        /// <summary>
        /// Handles opcode 6 by reading a public key from the packet,
        /// storing it, logging receipt, and broadcasting to other clients.
        /// </summary>
        private void HandlePublicKeyExchange()
        {
            // Reads the sender UID for context
            string senderUidStr = _packetReader.ReadMessage();

            // Reads the Base64 public key
            string publicKeyBase64 = _packetReader.ReadMessage();

            // Stores the public key locally
            PublicKeyBase64 = publicKeyBase64;
            PublicKeyDer = Convert.FromBase64String(publicKeyBase64);

            // Logs the reception of the public key
            Console.WriteLine(
                $"[DEBUG] Received public key from {Username} — UID: {senderUidStr}, length: {publicKeyBase64.Length}");

            // Broadcasts the key to all other connected clients
            Program.BroadcastPublicKeyToOthers(this);
        }

        /// <summary>
        /// Handles opcode 3 by reading the requester UID and sending
        /// each connected client's public key in response.
        /// </summary>
        private void HandlePublicKeySyncRequest()
        {
            // Reads the UID of the client requesting a sync
            string requesterUid = _packetReader.ReadMessage();

            // Logs the public-key sync request
            Console.WriteLine($"[DEBUG] Public key sync requested by UID: {requesterUid}");

            // Iterates through all connected clients
            foreach (var user in Program.Users)
            {
                // Skips users without a public key
                if (string.IsNullOrEmpty(user.PublicKeyBase64))
                    continue;

                try
                {
                    // Creates a packet for public key exchange
                    var packet = new PacketBuilder();
                    packet.WriteOpCode(6);
                    packet.WriteMessage(user.UID.ToString());
                    packet.WriteMessage(user.PublicKeyBase64);

                    // Sends the packet back to the requester
                    ClientSocket.GetStream()
                        .Write(packet.GetPacketBytes(), 0, packet.GetPacketBytes().Length);

                    // Logs the successful key send
                    Console.WriteLine(
                        $"[DEBUG] Sent public key of {user.Username} to {Username}");
                }
                catch (Exception ex)
                {
                    // Logs any failure in sending the key
                    Console.WriteLine(
                        $"[ERROR] Failed to send key to {Username}: {ex.Message}");
                }
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
