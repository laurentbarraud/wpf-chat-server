﻿/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.4</version>
/// <date>June 26th, 2024</date>

using chat_client.MVVM.ViewModel;
using chat_client.Net.IO;
using System.Net;
using System.Net.Sockets;
using System.Windows;

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
        public void ConnectToServer(string username, string IPAdressOfServer)
        {
            if (!_client.Connected)
            {
                if (IPAdressOfServer == "")
                {
                    // Localhost connection
                    _client.Connect("127.0.0.1", 7123);
                }

                else
                {
                    IPAddress serverIPAddress;
                    bool IPAddressValid = IPAddress.TryParse(IPAdressOfServer, out serverIPAddress);

                    if (IPAddressValid)
                    {
                        // Connection to the ip address provided
                        _client.Connect(IPAdressOfServer, 7123);
                    }

                    else
                    {
                        MessageBox.Show("The IP address is incorrect. Leave it blank to connect locally.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        MainViewModel.IsConnectedToServer = false;
                    }

                }

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
                try
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
                }
                catch (Exception ex)
                {
                    MessageBox.Show("The server has cut the connection. Restart the application to reconnect.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                    MainViewModel.IsConnectedToServer = false;
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
