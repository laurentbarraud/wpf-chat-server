using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace chat_client.Net
{
    internal class Server
    {
        TcpClient _client;

        public Server()
        {
            _client = new TcpClient();
        }

        public void ConnectToServer()
        {
            if (!_client.Connected)
            {
                _client.Connect("127.0.0.1", 7123);
            }
        }
    }
}
