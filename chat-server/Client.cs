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
        public string Username { get; set; }
        public Guid UID { get; set; }
        public TcpClient ClientSocket { get; set; }

        private readonly PacketReader _packetReader;

        /// <summary>
        /// RSA public key of the client, used for end-to-end encryption.
        /// This key is received from the client after connection and used by others to encrypt messages.
        /// </summary>
        public string PublicKeyBase64 { get; set; }


        public Client(TcpClient client)
        {
            ClientSocket = client;
            UID = Guid.NewGuid();
            _packetReader = new PacketReader(ClientSocket.GetStream());

            var opcode = _packetReader.ReadByte();
            Username = _packetReader.ReadMessage();

            // Localized connection message
            Console.WriteLine($"[{DateTime.Now}]: {LocalizationManager.GetString("ClientConnected")} {Username}");

            Task.Run(() => ListenForMessages());
        }

        /// <summary>
        /// Handles the reception of a public RSA key from a connected client.
        /// Stores the key locally and triggers broadcast to all other clients.
        /// Logs the key length and sender UID for traceability.
        /// </summary>
        /// <param name="reader">The packet reader used to extract the key.</param>
        internal void HandleIncomingPublicKey(PacketReader reader)
        {
            // Reads the Base64-encoded public key from the packet
            string publicKeyBase64 = reader.ReadMessage();

            // Stores the key in the client instance
            this.PublicKeyBase64 = publicKeyBase64;

            // Logs the reception for debugging
            Console.WriteLine($"[{DateTime.Now}]: Public key received from {Username} — Length: {publicKeyBase64.Length}");

            // Broadcasts the key to all other clients
            Program.BroadcastPublicKeyToOthers(this);
        }

        /// <summary>
        /// Continuously listens for incoming packets from the connected client.
        /// Handles supported opcodes and dispatches logic accordingly.
        /// Terminates the loop and triggers disconnect broadcast if an exception occurs.
        /// </summary>
        internal void ListenForMessages()
        {
            Console.WriteLine($"[SERVER] Listening for messages from {Username}...");

            while (true)
            {
                try
                {
                    // Reads the next opcode from the packet stream
                    var opcode = _packetReader.ReadByte();

                    switch (opcode)
                    {
                        case 5: // Chat message
                                // Reads the incoming message
                            var messageReceived = _packetReader.ReadMessage();

                            // Determines if the message is encrypted
                            string logMessage = messageReceived.StartsWith("[ENC]") ? "[ENC]" : messageReceived;

                            // Logs the received message
                            Console.WriteLine($"[{DateTime.Now}]: {LocalizationManager.GetString("MessageReceived")} {Username}: {logMessage}");

                            // Broadcasts the message to other connected clients
                            Program.BroadcastMessage(messageReceived, this.UID);
                            break;

                        case 6: // Public key exchange
                                // Reads the Base64-encoded public key
                            string publicKeyBase64 = _packetReader.ReadMessage();
                            this.PublicKeyBase64 = publicKeyBase64;

                            // Logs the key reception
                            Console.WriteLine($"[{DateTime.Now}]: Public key received from {Username} — Length: {publicKeyBase64.Length}");

                            // Broadcasts the key to other clients
                            Program.BroadcastPublicKeyToOthers(this);
                            break;

                        default:
                            // Logs unsupported opcode
                            Console.WriteLine($"[SERVER] Unknown opcode received from {Username}: {opcode}");
                            break;
                    }
                }
                catch (Exception)
                {
                    // Logs the disconnection event
                    Console.WriteLine($"[{DateTime.Now}]: {LocalizationManager.GetString("ClientDisconnected")} {Username}");

                    // Closes the socket and broadcasts the disconnect
                    ClientSocket.Close();
                    Program.BroadcastDisconnect(UID.ToString());
                    break;
                }
            }
        }
    }
}

