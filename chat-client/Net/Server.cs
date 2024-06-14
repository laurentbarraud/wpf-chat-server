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
                var connectPacket = new PacketBuilder();
                connectPacket.WriteOpCode(0);
                connectPacket.WriteString(username);
                _client.Client.Send(connectPacket.GetPacketBytes());
            }
        }
    }
}
