/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 24th, 2025</date>

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

            Console.WriteLine($"[SERVER] Listening for messages from {Username}...");
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
                        case 5: // Public chat message
                                // Reads sender UID and message content
                            string senderUidForMessage = _packetReader.ReadMessage();
                            string messageReceived = _packetReader.ReadMessage();

                            Console.WriteLine("[SERVER] Incoming message packet:");
                            Console.WriteLine($"         → Sender UID: {senderUidForMessage}");
                            Console.WriteLine($"         → Content: {(messageReceived.StartsWith("[ENC]") ? "[Encrypted]" : messageReceived)}");

                            // Broadcasts the message to all other connected clients
                            Program.BroadcastMessageToAll(messageReceived, Guid.Parse(senderUidForMessage));
                            break;

                        case 6: // Public key exchange
                                // Reads sender UID and public RSA key
                            string senderUidForKey = _packetReader.ReadMessage();
                            string publicKeyBase64 = _packetReader.ReadMessage();

                            // Stores the key locally and triggers broadcast to other clients
                            this.PublicKeyBase64 = publicKeyBase64;
                            Console.WriteLine($"[SERVER] Public key received from {Username} — UID: {senderUidForKey}, Length: {publicKeyBase64.Length}");
                            Program.BroadcastPublicKeyToOthers(this);
                            break;

                        default:
                            // Logs unknown opcodes for debugging and protocol validation
                            Console.WriteLine($"[SERVER] Unknown opcode received from {Username}: {opcode}");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    // Handles disconnection or stream failure gracefully
                    Console.WriteLine($"[{DateTime.Now}]: {LocalizationManager.GetString("ClientDisconnected")} {Username}");
                    ClientSocket.Close();
                    Program.BroadcastDisconnect(UID.ToString());

                    // Remove the disconnected client from the global list.
                    // This prevents reconnection issues if the same user (same pseudo) returns with a new UID
                    // It also ensures the server doesn't retain stale references to closed sockets
                    Program._users.Remove(this);
                    Console.WriteLine($"[SERVER] User removed from list of users — {this.Username} ({UID.ToString()})");

                    break;
                }
            }
        }
    }
}
