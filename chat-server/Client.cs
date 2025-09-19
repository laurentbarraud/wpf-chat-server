/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 19th, 2025</date>

using chat_server.Net.IO;
using chat_server.Helpers;
using System.Net.Sockets;

namespace chat_server
{
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
        /// RSA public key of the client, used for end-to-end encryption.
        /// This key is received from the client after connection and used by others to encrypt messages.
        /// </summary>
        public string PublicKeyBase64 { get; set; }

        /// <summary>
        /// Initializes a new client instance with the provided TCP socket and username.
        /// Instantiates the packet reader and assigns a unique identifier.
        /// </summary>
        /// <param name="client">The accepted TCP client socket.</param>
        /// <param name="username">The display name of the connected user.</param>
        public Client(TcpClient client, string username)
        {
            ClientSocket = client;
            Username = username;
            UID = Guid.NewGuid();

            // Initializes the packet reader for incoming messages
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
                                // Reads message content and sender UID
                            string messageReceived = _packetReader.ReadMessage();
                            string senderUidForMessage = _packetReader.ReadMessage();

                            // Broadcasts the message to all other connected clients
                            Program.BroadcastMessage(messageReceived, Guid.Parse(senderUidForMessage));
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
                    break;
                }
            }
        }
    }
}
