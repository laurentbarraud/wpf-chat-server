/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 10th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.Net.IO;
using Microsoft.VisualBasic.Logging;
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

        /// <summary>
        /// Establishes a TCP connection to the chat server using the specified IP address and username.
        /// This method is invoked from the MainViewModel during client initialization.
        /// It handles IP validation, port selection (default or custom), and initiates the handshake protocol.
        /// Upon successful connection, it initializes the packet reader and begins listening for incoming packets.
        /// Returns true if the connection succeeds; false otherwise.
        /// </summary>
        /// <param name="username">The display name of the user initiating the connection.</param>
        /// <param name="IPAddressOfServer">The target server IP address. If null or empty, defaults to localhost.</param>
        /// <returns>True if the connection is successfully established; false if an error occurs.</returns>
        public bool ConnectToServer(string username, string IPAddressOfServer)
        {
            // If already connected, no need to reconnect
            if (_client.Connected)
                return true;
            try
            {
                // Determine target IP: use localhost if no IP is provided
                string ipToConnect = string.IsNullOrWhiteSpace(IPAddressOfServer) ? "127.0.0.1" : IPAddressOfServer;

                // Validate IP format if not localhost
                if (ipToConnect != "127.0.0.1" && !IPAddress.TryParse(ipToConnect, out _))
                {
                    throw new ArgumentException(LocalizationManager.GetString("IPAddressInvalid"));
                }

                // Select port: use custom if enabled, otherwise default to 7123
                int portToUse = Properties.Settings.Default.UseCustomPort
                    ? Properties.Settings.Default.CustomPortNumber
                    : 7123;

                // Connect to server
                _client.Connect(ipToConnect, portToUse);

                // Initialize packet reader from network stream
                PacketReader = new PacketReader(_client.GetStream());

                // Send initial connection packet with username
                if (!string.IsNullOrEmpty(username))
                {
                    var connectPacket = new PacketBuilder();
                    connectPacket.WriteOpCode(0); // Opcode 0 = new user connection
                    connectPacket.WriteMessage(username);
                    _client.Client.Send(connectPacket.GetPacketBytes());
                }

                // Start listening for incoming packets
                ReadPackets();

                return true; // Connection successful
            }
            catch
            {
                return false; // Connection failed
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
                MessageBox.Show(LocalizationManager.GetString("ErrorWhileDisconnecting") + ex.Message, LocalizationManager.GetString("DisconnectError"), MessageBoxButton.OK, MessageBoxImage.Error);
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
                        mainViewModel.Messages.Add(LocalizationManager.GetString("ServerHasClosed"));

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

        /// <summary>
        /// Sends a message to the server using the standard message packet format.
        /// If encryption is enabled via application settings, the message is encrypted
        /// using the client's public key before transmission. Otherwise, it is sent as plain text.
        /// </summary>

        public void SendMessageToServer(string message)
        {
            // If encryption is enabled in application settings, encrypt the message before sending
            bool encryptionEnabled = chat_client.Properties.Settings.Default.UseEncryption;

            if (encryptionEnabled)
            {
                // Prefix the encrypted message with a marker to indicate its format.
                // This allows receiving clients to detect whether the message should be decrypted.
                // Without this, clients may attempt to decrypt plain text, causing failures.
                message = "[ENC]" + EncryptionHelper.EncryptMessage(message);
            }

            var messagePacket = new PacketBuilder();

            // We use opcode 5 for messages packets
            messagePacket.WriteOpCode(5);
            messagePacket.WriteMessage(message);
            
            // This avoids silently failed shipments
            if (_client == null || !_client.Connected)
            {
                Console.WriteLine(LocalizationManager.GetString("ClientSocketNotConnected"));
                return;
            }
            // Send the message packet through the TCP client socket
            _client.Client.Send(messagePacket.GetPacketBytes());
        }

        /// <summary>
        /// Sends a raw packet directly to the server using the TCP client socket.
        /// This is useful for non-standard packets such as public key exchange.
        /// </summary>
        public void SendRawPacket(byte[] data)
        {
            if (_client?.Client != null && _client.Connected)
            {
                _client.Client.Send(data);
            }
        }
    }
}
