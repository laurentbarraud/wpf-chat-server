/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.5</version>
/// <date>August 24th, 2025</date>

using chat_server.Net.IO;
using System.Net.Sockets;

namespace chat_server
{
    class Client
    {
        public string Username { get; set; }
        public Guid UID { get; set; }
        public TcpClient ClientSocket { get; set; }

        PacketReader _packetReader;
        public Client(TcpClient client)
        {
            ClientSocket = client;
            UID = Guid.NewGuid();
            _packetReader = new PacketReader(ClientSocket.GetStream());
            
            var opcode = _packetReader.ReadByte();
            Username = _packetReader.ReadMessage();

            Console.WriteLine($"[{DateTime.Now}]: Client has connected with the username: {Username}");

            Task.Run(() => Process());
        }

        void Process()
        {
            while(true)
            {
                try
                {
                    var opcode = _packetReader.ReadByte();
                    switch (opcode)
                    {
                        case 5:
                            var messageReceived = _packetReader.ReadMessage();
                            Console.WriteLine($"[{DateTime.Now}]: Message received from {Username}: {messageReceived}");
                            Program.BroadcastMessage($"{Username}: " + $"{messageReceived}");
                            break;
                        default:
                            break;
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine($"[{DateTime.Now}]: {Username.ToString()} disconnected!");

                    // Will dispose the actual object as well and then closes it.
                    ClientSocket.Close();

                    Program.BroadcastDisconnect(UID.ToString());
                    break;
                }
            }
        }
    }
}
