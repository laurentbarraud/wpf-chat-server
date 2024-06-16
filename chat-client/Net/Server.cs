/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.3</version>
/// <date>June 16th, 2024</date>

using chat_client.Net.IO;
using System.Net.Sockets;

namespace chat_client.Net
{
    public class Server
    {
        TcpClient _client;
        public PacketBuilder PacketBuilder;
        public PacketReader PacketReader;

        public event Action connectedEvent;
        public event Action msgReceivedEvent;
        public event Action userDisconnectEvent;

        public Server()
        {
            _client = new TcpClient();
        }

        // We're calling this from the MainViewModel
        public void ConnectToServer(string username)
        {
            if (!_client.Connected)
            {
                _client.Connect("127.0.0.1", 7123);

                // If the connection is successfull
                PacketReader = new PacketReader(_client.GetStream());

                if (!string.IsNullOrEmpty(username))
                {
                    var connectPacket = new PacketBuilder();
                    
                    // We use opcode 0 for "connection of a new user" packets
                    connectPacket.WriteOpCode(0);
                    connectPacket.WriteMessage(username);

                    // We send the message packet through the Client socket,
                    // in the TCPClient 
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
                    
                    // opcode 0 is handled somewhere else
                    switch (opcode)
                    {
                        case 1:
                            connectedEvent?.Invoke();
                            break;

                        case 5:
                            msgReceivedEvent?.Invoke();
                            break;

                        case 10:
                            userDisconnectEvent?.Invoke();
                            break;
                    }
                }
            });
        }

        public void SendMessageToServer(string message)
        {
            var messagePacket = new PacketBuilder();

            // We use opcode 5 for messages packets
            messagePacket.WriteOpCode(5);
            messagePacket.WriteMessage(message);

            // We send the message packet through the Client socket,
            // in the TCPClient 
            _client.Client.Send(messagePacket.GetPacketBytes());
        }
    }
}
