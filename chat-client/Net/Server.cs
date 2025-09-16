/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 15th, 2025</date>

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
        /// If encryption is enabled and LocalUser is initialized, it triggers key exchange setup.
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

                // Trigger encryption setup if enabled and LocalUser is initialized
                (Application.Current.MainWindow as MainWindow)?.TriggerEncryptionIfNeeded();

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
        /// Handles the reception of a public RSA key from another connected client.
        /// Extracts the sender's UID and public key from the packet,
        /// and stores the key in the ViewModel's KnownPublicKeys dictionary.
        /// Ensures thread-safe UI access via Dispatcher.
        /// </summary>
        /// <param name="reader">The packet reader used to extract incoming data.</param>
        private void HandleIncomingPublicKey(PacketReader reader)
        {
            string senderUID = reader.ReadMessage();
            string publicKeyBase64 = reader.ReadMessage();

            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow &&
                    mainWindow.ViewModel is MainViewModel viewModel)
                {
                    viewModel.ReceivePublicKey(senderUID, publicKeyBase64);
                    Console.WriteLine($"[INFO] Public key received and stored for UID: {senderUID}");
                }
                else
                {
                    Console.WriteLine($"[WARN] Unable to store public key for UID {senderUID}: ViewModel not available.");
                }
            });
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
                                HandleIncomingPublicKey(PacketReader);
                                break;

                            case 10:
                                // Triggers user disconnect event
                                userDisconnectEvent?.Invoke();
                                break;

                            default:
                                Console.WriteLine($"[WARN] Unknown opcode received: {opcode}");
                                break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] Packet reading failed: {ex.Message}");

                    // Handles disconnection or stream failure gracefully
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        if (Application.Current.MainWindow is not MainWindow mainWindow ||
                            mainWindow.ViewModel is not MainViewModel mainViewModel)
                            return;

                        // Notifies user in chat
                        mainViewModel.Messages.Add(LocalizationManager.GetString("ServerHasClosed"));

                        // Show banner without icon
                        mainWindow.ShowBanner("ServerHasClosed");

                        // Immediately reset UI state
                        mainViewModel.ReinitializeUI();
                    });
                }
            });
        }

        /// <summary>
        /// Sends the client's public RSA key to the server for distribution to other connected clients.
        /// Builds a packet with OpCode 6, including the sender's UID, username, and public key in Base64 format.
        /// Returns true only if the underlying socket exists and is actively connected.
        /// This method is used during encryption setup and must be reliable to ensure secure key exchange.
        /// Designed to fail silently if the client is disconnected, allowing upstream logic to handle rollback and user feedback.
        /// </summary>
        /// <param name="uid">The UID of the sender.</param>
        /// <param name="username">The username of the sender.</param>
        /// <param name="publicKeyBase64">The public RSA key in Base64 format.</param>
        /// <returns>True if the packet was sent successfully; false if the client is not connected.</returns>
        public bool SendPublicKeyToServer(string uid, string username, string publicKeyBase64)
        {
            // Builds encryption packet with OpCode 6 (public key exchange)
            var packet = new PacketBuilder();
            packet.WriteOpCode(6); // OpCode for public key exchange
            packet.WriteMessage(uid); // Sender UID
            packet.WriteMessage(username); // Sender username
            packet.WriteMessage(publicKeyBase64); // Public key in Base64

            // Sends packet only if client is connected
            if (_client?.Client != null && _client.Connected)
            {
                _client.Client.Send(packet.GetPacketBytes());
                return true;
            }

            // Failed to send (client not connected)
            return false;
        }

        /// <summary>
        /// Sends a message to the server using the standard message packet format.
        /// If encryption is enabled via application settings, the message is encrypted
        /// using the recipient's public key before transmission. Otherwise, it is sent as plain text.
        /// </summary>
        /// <param name="message">The plain text message to send.</param>
        public void SendMessageToServer(string message)
        {
            // Retrieve ViewModel safely and exit if unavailable
            if (Application.Current.MainWindow is not MainWindow mainWindow || mainWindow.ViewModel is not MainViewModel viewModel)
            {
                Console.WriteLine("[ERROR] ViewModel is null. Cannot send message.");
                return;
            }

            // Retrieve sender UID
            string senderUID = viewModel.LocalUser?.UID ?? "unknown";

            // Retrieve recipient UID
            string? recipientUID = viewModel.SelectedUser?.UID;

            // Encrypt the message if encryption is enabled and recipient UID is valid
            if (viewModel.IsEncryptionEnabled && !string.IsNullOrEmpty(recipientUID))
            {
                if (viewModel.KnownPublicKeys.TryGetValue(recipientUID, out string? publicKeyBase64) && !string.IsNullOrEmpty(publicKeyBase64))
                {
                    string encrypted = EncryptionHelper.EncryptMessage(message, publicKeyBase64);
                    message = "[ENC]" + encrypted;
                }
                else
                {
                    Console.WriteLine($"[WARN] Public key for UID {recipientUID} not found or invalid. Message sent as plain text.");
                }
            }

            // Build and send the message packet
            var messagePacket = new PacketBuilder();
            messagePacket.WriteOpCode(5); // Public chat message
            messagePacket.WriteMessage(message);
            messagePacket.WriteMessage(senderUID);

            if (_client == null || !_client.Connected)
            {
                Console.WriteLine(LocalizationManager.GetString("ClientSocketNotConnected"));
                return;
            }

            _client.Client.Send(messagePacket.GetPacketBytes());
        }
    }
}
