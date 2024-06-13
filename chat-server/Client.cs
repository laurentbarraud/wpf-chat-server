using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace chat_server
{
    class Client
    {
        public string Username { get; set; }
        public Guid UID { get; set; }
        public TcpClient ClientSocket { get; set; }
        public Client(TcpClient client)
        {
            ClientSocket = client;
            UID = Guid.NewGuid();

            Console.WriteLine($"[{DateTime.Now}]: Client has connected with the username: {Username}");
        }
    }
}
