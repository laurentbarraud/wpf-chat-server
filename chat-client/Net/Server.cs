/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.7</version>
/// <date>September 2nd, 2025</date>

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

        /// <summary>
        /// Indicates whether the client is currently connected to the server.
        /// Returns true if the TCP client exists and is connected; otherwise, false.
        /// </summary>
        public bool IsConnected => _client?.Connected ?? false;

        public Server()
        {
            _client = new TcpClient();
        }

        // We're calling this from the MainViewModel
        public bool ConnectToServer(string username, string IPAddressOfServer)
        {
            // If already connected, no need to reconnect
            if (_client.Connected)
                return true;

            try
            {
                // Determines which IP to connect to: localhost or user-provided
                string ipToConnect = string.IsNullOrWhiteSpace(IPAddressOfServer) ? "127.0.0.1" : IPAddressOfServer;

                // Validates IP format if not localhost
                if (ipToConnect != "127.0.0.1" && !IPAddress.TryParse(ipToConnect, out _))
                {
                    // Invalid IP format — throw exception to be caught by caller
                    throw new ArgumentException("The IP address is incorrect. Leave it blank to connect locally.");
                }

                // Attempts to connect to the server on port 7123
                _client.Connect(ipToConnect, 7123);

                // Initializes the packet reader using the network stream
                PacketReader = new PacketReader(_client.GetStream());

                // Sends initial connection packet with username
                if (!string.IsNullOrEmpty(username))
                {
                    var connectPacket = new PacketBuilder();
                    connectPacket.WriteOpCode(0); // Opcode 0 = new user connection
                    connectPacket.WriteMessage(username);
                    _client.Client.Send(connectPacket.GetPacketBytes());
                }

                // Starts listening for incoming packets
                ReadPackets();

                // Connection successful
                return true;
            }
            catch
            {
                // Connection failed — return false to be handled by caller
                return false;
            }
        }


        /// <summary>
        /// Closes the TCP connection and resets internal state
        /// </summary>
        public void DisconnectFromServer()
        {
            try
            {
                // Close the TCP connection if it's active
                if (_client != null && _client.Connected)
                {
                    _client.Close();
                }

                // Reset internal objects
                PacketReader = null;
                PacketBuilder = null;

                // Reinitialize the TcpClient so we can reconnect later
                _client = new TcpClient();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error while disconnecting: {ex.Message}", "Disconnect Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


        /// <summary>
        /// Continuously reads incoming packets from the server.
        /// Handles known opcodes and manages disconnection on failure.
        /// </summary>
        private void ReadPackets()
        {
            Task.Run(() =>
            {
                try
                {
                    while (_client.Connected)
                    {
                        // Read the first byte (opcode)
                        var opcode = PacketReader.ReadByte();

                        // Dispatch based on opcode
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

                                // Add more opcodes as needed
                        }
                    }
                }
                catch (Exception)
                {
                    // Handle disconnection or stream failure
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        var mainWindow = Application.Current.MainWindow as MainWindow;
                        if (mainWindow == null) return;

                        var mainViewModel = mainWindow.ViewModel;
                        if (mainViewModel == null) return;

                        // Notify user in chat
                        mainViewModel.Messages.Add("Server has closed. You will be disconnected shortly...");

                        // Create a timer to delay UI reset
                        var timer = new System.Timers.Timer(2000);
                        timer.AutoReset = false; // Only fire once
                        timer.Elapsed += (s, e) =>
                        {
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                // Reset UI state
                                mainViewModel.ReinitializeUI();
                            });
                        };

                        timer.Start();
                    });
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
