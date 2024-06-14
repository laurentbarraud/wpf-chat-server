using chat_client.Net.IO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace chat_client.Net
{
    class Server
    {
        TcpClient _client;
        public PacketReader PacketReader;

        public event Action connectedEvent;

        public Server()
        {
            _client = new TcpClient();
        }

        // We're calling this from the ViewModel
        public void ConnectToServer(string username)
        {
            if (!_client.Connected)
            {
                _client.Connect("127.0.0.1", 7123);
                // If the connection is successfull
                PacketReader = new PacketReader(_client.GetStream());
                
                if(!_client.Connected)
                {
                    var connectPacket = new PacketBuilder();
                    connectPacket.WriteOpCode(0);
                    connectPacket.WriteString(username);
                    _client.Client.Send(connectPacket.GetPacketBytes());
                }
                ReadPackets();
            }
        }

        private void ReadPackets()
        {
            Task.Run(() =>
            {
                while (true)
                {
                    // Reads the first byte (opcode) and stores it
                    var opcode = PacketReader.ReadByte();
                    
                    // We don't do anything if the opcode value is 0
                    switch (opcode)
                    {
                        case 1:
                            connectedEvent?.Invoke();
                            break;
                        default:
                            Console.WriteLine("Error reading the opcode.");
                            break;
                    }
                }
            });
        }
    }
}
