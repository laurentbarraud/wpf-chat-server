/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.6.1</version>
/// <date>September 2nd, 2025</date>

using chat_server.Net.IO;
using System.Net;
using System.Net.Sockets;

namespace chat_server
{
    public class Program
    {
        static List<Client> _users;
        static TcpListener _listener;
        public static void Main(string[] args)
        {
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Shutdown();
                Environment.Exit(0);
            };

            _users = new List<Client>();
            _listener = new TcpListener(IPAddress.Parse("127.0.0.1"), 7123);
            _listener.Start();

            while (true)
            {
                var client = new Client(_listener.AcceptTcpClient());
                _users.Add(client);

                BroadcastConnection();
            }
        }

        /// <summary>
        /// Sends a packet to each logged in user, 
        /// with an opcode of 1, meaning that
        /// a new user has logged in.
        /// </summary>
        public static void BroadcastConnection()
        {
            foreach (var user in _users)
            {
                foreach (var usr in _users)
                {
                    var broadcastPacket = new PacketBuilder();
                    broadcastPacket.WriteOpCode(1);
                    broadcastPacket.WriteMessage(usr.Username);
                    broadcastPacket.WriteMessage(usr.UID.ToString());
                    user.ClientSocket.Client.Send(broadcastPacket.GetPacketBytes());
                }
            }
        }

        public static void BroadcastMessage(string messageToBroadcast)
        {
            foreach (var user in _users)
            {
                var msgPacket = new PacketBuilder();
                msgPacket.WriteOpCode(5);
                msgPacket.WriteMessage(messageToBroadcast);
                user.ClientSocket.Client.Send(msgPacket.GetPacketBytes());
            }
        }

        public static void BroadcastDisconnect(string uidDisconnected)
        {
            var disconnectedUser = _users.Where(x => x.UID.ToString() == uidDisconnected).FirstOrDefault();
            
            if (disconnectedUser != null) 
            { 
                _users.Remove(disconnectedUser); 

                foreach (var user in _users)
                {
                    var broadcastPacket = new PacketBuilder();
                    broadcastPacket.WriteOpCode(10);
                    broadcastPacket.WriteMessage(uidDisconnected);
                    user.ClientSocket.Client.Send(broadcastPacket.GetPacketBytes());
                }

                BroadcastMessage($"Server: {disconnectedUser.Username} disconnected!");
            }
        }
        public static void Shutdown()
        {
            Console.WriteLine("Shutting down server...");
            BroadcastMessage("/disconnect"); // Special command for client to disconnect
            Console.WriteLine("Server shutdown complete.");
        }
    }
}