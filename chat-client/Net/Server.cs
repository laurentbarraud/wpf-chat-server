/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.6</version>
/// <date>September 1st, 2025</date>

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
                                mainWindow.cmdConnect.Content = "_Connect";
                                mainWindow.txtUsername.IsEnabled = true;
                                mainWindow.txtIPAddress.IsEnabled = true;

                                mainViewModel.Users.Clear();
                                mainViewModel.Messages.Clear();

                                mainWindow.Title = "WPF Chat Server";
                                mainWindow.spnCenter.Visibility = Visibility.Hidden;
                                MainViewModel.IsConnectedToServer = false;
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
