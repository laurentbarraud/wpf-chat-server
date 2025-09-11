/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 11th, 2025</date>

using chat_server.Net.IO;
using chat_server.Helpers;
using System.Net.Sockets;

namespace chat_server
{
    class Client
    {
        public string Username { get; set; }
        public Guid UID { get; set; }
        public TcpClient ClientSocket { get; set; }

        private readonly PacketReader _packetReader;

        public Client(TcpClient client)
        {
            ClientSocket = client;
            UID = Guid.NewGuid();
            _packetReader = new PacketReader(ClientSocket.GetStream());

            var opcode = _packetReader.ReadByte();
            Username = _packetReader.ReadMessage();

            // Localized connection message
            Console.WriteLine($"[{DateTime.Now}]: {LocalizationManager.GetString("ClientConnected")} {Username}");

            Task.Run(() => Process());
        }

        void Process()
        {
            while (true)
            {
                try
                {
                    var opcode = _packetReader.ReadByte();
                    switch (opcode)
                    {
                        case 5:
                            var messageReceived = _packetReader.ReadMessage();

                            // Checks if the message starts with [ENC]
                            string logMessage = messageReceived.StartsWith("[ENC]") ? "[ENC]" : messageReceived;

                            // Localized message received log
                            Console.WriteLine($"[{DateTime.Now}]: {LocalizationManager.GetString("MessageReceived")} {Username}: {logMessage}");

                            // Broadcasts the full message to other clients
                            Program.BroadcastMessage($"{Username}: {messageReceived}");
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

