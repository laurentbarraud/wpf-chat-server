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
        /// Dispatches known opcodes and handles disconnection gracefully.
        /// </summary>
        private void ReadPackets()
        {
            Task.Run(() =>
            {
                try
                {
                    while (_client.Connected)
                    {
                        // Reads the first byte from the stream — this is the opcode
                        var opcode = PacketReader.ReadByte();

                        // Dispatches logic based on opcode value
                        switch (opcode)
                        {
                            case 1:
                                // Triggers connection event (e.g., user joined)
                                connectedEvent?.Invoke();
                                break;

                            case 5:
                                // Triggers message received event
                                msgReceivedEvent?.Invoke();
                                break;

                            case 6:
                                // Handles public key exchange from another client
                                string senderUID = PacketReader.ReadMessage();
                                string publicKeyBase64 = PacketReader.ReadMessage();

                                // Registers the received public key in the ViewModel
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    if (Application.Current.MainWindow is MainWindow mainWindow &&
                                        mainWindow.ViewModel != null)
                                    {
                                        mainWindow.ViewModel.KnownPublicKeys[senderUID] = publicKeyBase64;
                                        Console.WriteLine($"Received public key from {senderUID}");
                                    }
                                });
                                break;

                            case 10:
                                // Triggers user disconnect event
                                userDisconnectEvent?.Invoke();
                                break;
                        }
                    }
                }
                catch (Exception)
                {
                    // Handles disconnection or stream failure gracefully
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        if (Application.Current.MainWindow is not MainWindow mainWindow ||
                            mainWindow.ViewModel is not MainViewModel mainViewModel)
                            return;

                        // Notifies user in chat
                        mainViewModel.Messages.Add(LocalizationManager.GetString("ServerHasClosed"));

                        // Delays UI reset to allow user to read the message
                        var timer = new System.Timers.Timer(2000)
                        {
                            AutoReset = false // Fire only once
                        };

                        timer.Elapsed += (s, e) =>
                        {
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                // Resets UI state (e.g., reconnect button, input fields)
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
        /// using the recipient's public key before transmission. Otherwise, it is sent as plain text.
        /// </summary>
        /// <param name="message">The plain text message to send.</param>
        public void SendMessageToServer(string message)
        {
            bool encryptionEnabled = chat_client.Properties.Settings.Default.UseEncryption;

            if (encryptionEnabled)
            {
                // Encrypt the message with the sender's own public key
                string encrypted = EncryptionHelper.EncryptMessage(message, EncryptionHelper.GetPublicKeyBase64());


                // Prefix with marker so receivers know it's encrypted
                message = "[ENC]" + encrypted;
            }

            var messagePacket = new PacketBuilder();
            messagePacket.WriteOpCode(5); // OpCode for public chat message
            messagePacket.WriteMessage(message);
            var uid = (Application.Current.MainWindow as MainWindow)?.ViewModel?.LocalUser?.UID;
            messagePacket.WriteMessage(uid ?? "unknown");   // Include sender UID so others can decrypt

            if (_client == null || !_client.Connected)
            {
                Console.WriteLine(LocalizationManager.GetString("ClientSocketNotConnected"));
                return;
            }

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
