/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 18th, 2025</date>

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
        /// Handles the reception of a public RSA key from a connected client.
        /// Stores the key locally and triggers broadcast to all other clients.
        /// Logs the key length and sender UID for traceability.
        /// </summary>
        /// <param name="reader">The packet reader used to extract the key.</param>
        internal void HandleIncomingPublicKey(PacketReader reader)
        {
            string publicKeyBase64 = reader.ReadMessage();
            this.PublicKeyBase64 = publicKeyBase64;

            Console.WriteLine($"[{DateTime.Now}]: Public key received from {Username} — Length: {publicKeyBase64.Length}");
            Program.BroadcastPublicKeyToOthers(this);
        }

        /// <summary>
        /// Continuously listens for incoming packets from the connected client.
        /// Handles supported opcodes and dispatches logic accordingly.
        /// Terminates the loop and triggers disconnect broadcast if an exception occurs.
        /// </summary>
        internal void ListenForMessages()
        {
            while (true)
            {
                try
                {
                    // Reads the next opcode from the packet stream
                    var opcode = _packetReader.ReadByte();

                    switch (opcode)
                    {
                        case 5: // Chat message
                            string messageReceived = _packetReader.ReadMessage();
                            Program.BroadcastMessage(messageReceived, this.UID);
                            break;

                        case 6: // Public key exchange
                            string publicKeyBase64 = _packetReader.ReadMessage();
                            this.PublicKeyBase64 = publicKeyBase64;
                            Program.BroadcastPublicKeyToOthers(this);
                            break;

                        default:
                            Console.WriteLine($"[SERVER] Unknown opcode received from {Username}: {opcode}");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[{DateTime.Now}]: {LocalizationManager.GetString("ClientDisconnected")} {Username}");
                    ClientSocket.Close();
                    Program.BroadcastDisconnect(UID.ToString());
                    break;
                }
            }
        }
    }
}
