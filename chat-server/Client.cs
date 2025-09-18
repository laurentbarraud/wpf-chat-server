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

            Task.Run(() => ListenForMessagesProcess());
        }

        void ListenForMessagesProcess()
        {
            while (true)
            {
                try
                {
                    var opcode = _packetReader.ReadByte();
                    switch (opcode)
                    {
                        case 5:
                            // Read the incoming message from the client
                            var messageReceived = _packetReader.ReadMessage();

                            // Checks if the message starts with [ENC]
                            string logMessage = messageReceived.StartsWith("[ENC]") ? "[ENC]" : messageReceived;

                            // Localized message received log
                            Console.WriteLine($"[{DateTime.Now}]: {LocalizationManager.GetString("MessageReceived")} {Username}: {logMessage}");

                            // Broadcasts the raw message and sender UID to other clients
                            Program.BroadcastMessage(messageReceived, this.UID);
                            break;

                        case 6: // Public key exchange
                            string publicKeyBase64 = _packetReader.ReadMessage();
                            this.PublicKeyBase64 = publicKeyBase64;

                            // Broadcast to other clients
                            Program.BroadcastPublicKeyToOthers(this);
                            break;
                    }
                }
                catch (Exception)
                {
                    // Localized disconnect message
                    Console.WriteLine($"[{DateTime.Now}]: {LocalizationManager.GetString("ClientDisconnected")} {Username}");

                    ClientSocket.Close();
                    Program.BroadcastDisconnect(UID.ToString());
                    break;
                }
            }
        }
    }
}

