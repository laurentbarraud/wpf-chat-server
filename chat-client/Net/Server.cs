/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.MVVM.ViewModel;
using chat_client.Net.IO;
using ChatClient.Helpers;
using System.Drawing;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows;

namespace chat_client.Net
{
    /// <summary>
    /// Represents the client-side connection to the server.
    /// Manages packet construction and reading, and exposes events for packet-driven updates.
    /// Events are subscribed by MainViewModel to handle user connection, message reception, and disconnection.
    /// </summary>
    public class Server
    {
        TcpClient _client;

        /// <summary>Used to build outgoing packets.</summary>
        public PacketBuilder PacketBuilder;

        /// <summary>Used to read incoming packets from the server stream.</summary>
        public PacketReader PacketReader;

        /// <summary>Triggered when a new user joins (opcode 1).</summary>
        public event Action connectedEvent;

        /// <summary>Triggered when a message is received (opcode 5).</summary>
        public event Action msgReceivedEvent;

        /// <summary>Triggered when a user disconnects (opcode 10).</summary>
        public event Action userDisconnectEvent;

        private Guid _localUid;
        private string _localPublicKey;

        public Guid GetLocalUid() => _localUid;
        public string GetLocalPublicKey() => _localPublicKey;


        /// <summary>
        /// Indicates whether the client is currently connected to the server.
        /// Returns true if the TCP client exists and is connected; otherwise, false.
        /// </summary>
        public bool IsConnected => _client?.Connected ?? false;

        /// <summary>
        /// Indicates whether the server has acknowledged the client's identity.
        /// Blocks outgoing packets until the handshake is complete.
        /// </summary>
        public bool HandshakeCompleted { get; private set; } = false;

        public Server()
        {
            _client = new TcpClient();
        }

        /// <summary>
        /// Establishes a TCP connection to the chat server using the specified IP address and username.
        /// Validates the IP format and selects the appropriate port.
        /// Generates a unique UID and RSA public key to identify the client during handshake.
        /// Initializes the packet reader and delegates the handshake to SendInitialConnectionPacket().
        /// Returns the generated UID and public key if the connection succeeds; otherwise returns empty values.
        /// Designed for traceable identity and secure session initialization.
        /// </summary>
        /// <param name="username">The display name of the user initiating the connection.</param>
        /// <param name="IPAddressOfServer">The target server IP address. Defaults to localhost if null or empty.</param>
        /// <returns>A tuple containing the UID and public key if successful; otherwise (Guid.Empty, null).</returns>
        public (Guid uid, string publicKeyBase64) ConnectToServer(string username, string IPAddressOfServer)
        {
            try
            {
                // Determines the target IP; falls back to localhost if none is provided
                string ipToConnect = string.IsNullOrWhiteSpace(IPAddressOfServer) ? "127.0.0.1" : IPAddressOfServer;

                // Validates the IP format if not localhost
                if (ipToConnect != "127.0.0.1" && !IPAddress.TryParse(ipToConnect, out _))
                {
                    throw new ArgumentException(LocalizationManager.GetString("IPAddressInvalid"));
                }

                // Selects the port; uses custom if enabled, otherwise defaults to 7123
                int portToUse = Properties.Settings.Default.UseCustomPort
                    ? Properties.Settings.Default.CustomPortNumber
                    : 7123;

                // Establishes the TCP connection
                _client.Connect(ipToConnect, portToUse);
                ClientLogger.Log($"TCP connection established — IP: {ipToConnect}, Port: {portToUse}", LogLevel.Debug);

                // Initializes the packet reader from the network stream
                PacketReader = new PacketReader(_client.GetStream());

                // Generates UID and RSA public key for handshake
                Guid uid = Guid.NewGuid();
                string publicKeyBase64 = EncryptionHelper.GetPublicKeyBase64();

                ClientLogger.Log($"UID generated for handshake: {uid}", LogLevel.Debug);
                ClientLogger.Log($"RSA public key generated: {publicKeyBase64}", LogLevel.Debug);

                // Sends the initial connection packet and starts listening
                if (!SendInitialConnectionPacket(username, uid, publicKeyBase64))
                    throw new Exception("Failed to send initial connection packet.");

                // Stores UID and public key locally for reference
                _localUid = uid;
                _localPublicKey = publicKeyBase64;

                return (uid, publicKeyBase64);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"[ERROR] Connection failed: {ex.Message}", LogLevel.Error);
                return (Guid.Empty, null);
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
        /// Returns all known public RSA keys for connected users.
        /// Keys may include the caller's own key; filtering is done client-side.
        /// Filters out users with missing UID or public key.
        /// After checking, we tell the compiler that the values are safe to use.
        /// </summary>
        public Dictionary<string, string> GetAllKnownPublicKeys(MainViewModel viewModel)
        {
            // Returns an empty dictionary if viewModel or Users list is null
            if (viewModel?.Users == null)
                return new Dictionary<string, string>();

            return viewModel.Users
                // Filters out users with null or empty UID or public key
                .Where(u => !string.IsNullOrEmpty(u.UID) && !string.IsNullOrEmpty(u.PublicKeyBase64))
                // Uses ! to assert non-nullability after filtering
                .ToDictionary(u => u.UID!, u => u.PublicKeyBase64!);
        }


        /// <summary>
        /// Processes an incoming RSA public key packet from a peer.
        /// Reads senderUid and Base64-encoded public key,  
        /// delegates registration to the ViewModel for centralized key storage and sync logic,  
        /// and triggers a key-synchronization check.  
        /// Ensures UI thread safety and logs warnings when the ViewModel is unavailable.
        /// </summary>
        /// <param name="reader">The packet reader extracting data from the incoming stream.</param>
        private static void HandleIncomingPublicKey(PacketReader reader)
        {
            // Reads the UID of the peer who sent the key
            string senderUid = reader.ReadMessage();

            // Reads the Base64-encoded RSA public key
            string publicKeyBase64 = reader.ReadMessage();

            // Invokes registration on the UI thread for thread safety
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow
                    && mainWindow.ViewModel is MainViewModel viewModel)
                {
                    // Registers the incoming public key
                    viewModel.ReceivePublicKey(senderUid, publicKeyBase64);

                    // Triggers synchronization logic to confirm full key set
                    viewModel.SyncKeys();
                }
                else
                {
                    ClientLogger.Log($"Cannot register public key for {senderUid}: ViewModel unavailable.", LogLevel.Warn);
                }
            });
        }

        /// <summary>
        /// Continuously reads incoming packets from the server on a background thread.
        /// Dispatches logic based on opcode values and triggers corresponding events:
        /// - Opcode 1: triggers connection event and marks handshake as complete
        /// - Opcode 5: triggers message received event
        /// - Opcode 6: handles incoming public key
        /// - Opcode 10: triggers user disconnect event
        /// Handles disconnection gracefully and resets UI state if the stream fails.
        /// This method is central to client-side packet routing and real-time updates.
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
                                HandshakeCompleted = true;
                                ClientLogger.Log("Handshake completed — client may now send packets.", LogLevel.Debug);
                                break;

                            case 5:
                                // Triggers message received event
                                msgReceivedEvent?.Invoke();
                                break;

                            case 6:
                                // Handles incoming public key from another client
                                HandleIncomingPublicKey(PacketReader);
                                break;

                            case 10:
                                // Triggers user disconnect event
                                userDisconnectEvent?.Invoke();
                                break;

                            default:
                                ClientLogger.Log($"Unknown opcode received: {opcode}", LogLevel.Warn);
                                break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"Packet reading failed: {ex.Message}", LogLevel.Error);

                    // Handles disconnection or stream failure gracefully
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        if (Application.Current.MainWindow is not MainWindow mainWindow ||
                            mainWindow.ViewModel is not MainViewModel mainViewModel)
                            return;

                        mainViewModel.Messages.Add(LocalizationManager.GetString("ServerHasClosed"));
                        mainViewModel.ReinitializeUI();
                    });
                }
            });
        }

        /// <summary>
        /// Sends a request to the server asking for all known public keys.
        /// This triggers a series of opcode 6 packets in response.
        /// </summary>
        public void RequestAllPublicKeysFromServer()
        {
            var packet = new PacketBuilder();
            packet.WriteOpCode(3); // Opcode for public key sync request
            packet.WriteMessage(_localUid.ToString());

            // Sends the packet to the server via the active socket stream
            _client.GetStream().Write(
                packet.GetPacketBytes(),
                0,
                packet.GetPacketBytes().Length
            );

            ClientLogger.Log($"Public key sync request sent — UID: {_localUid.ToString()}", LogLevel.Debug);
        }


        /// <summary>
        /// Resends the client's public RSA key to the server for recovery or synchronization purposes.
        /// Typically called when key distribution fails or when a new client joins and requires the key.
        /// Ensures that the server and all connected clients have access to the sender's encryption identity.
        /// Designed to be safe and idempotent — skips transmission if prerequisites are missing.
        /// </summary>
        public void ResendPublicKey()
        {
            // Validates prerequisites before attempting to resend
            if (_localUid == Guid.Empty || string.IsNullOrEmpty(_localPublicKey))
            {
                ClientLogger.Log("Cannot resend public key — UID or key is missing.", LogLevel.Warn);
                return;
            }

            // Sends the public key to the server for redistribution
            SendPublicKeyToServer(_localUid.ToString(), _localPublicKey);
            ClientLogger.Log("Public key resent manually — UID: " + _localUid, LogLevel.Debug);
        }

/// <summary>
/// Sends the initial connection packet to the server using opcode 0.  
/// Includes the username, UID, and public RSA key for handshake identity.
/// Starts listening for incoming packets.  
/// Returns true if the packet is sent successfully; false otherwise.
/// </summary>
/// <param name="username">The display name of the user.</param>
/// <param name="uid">The unique identifier assigned to the client during connection.</param>
/// <param name="publicKeyBase64">The RSA public key used for encryption handshake.</param>
/// <returns>True if the packet is sent and listening begins; false otherwise.</returns>
public bool SendInitialConnectionPacket(string username, Guid uid, string publicKeyBase64)
    {
        if (string.IsNullOrEmpty(username))
            return false;

        try
        {
            // Constructs the handshake packet with identity and encryption capability
            var connectPacket = new PacketBuilder();
            connectPacket.WriteOpCode(0);                       // Opcode 0 = new user connection
            connectPacket.WriteMessage(username);               // Writes the Username
            connectPacket.WriteMessage(uid.ToString());         // Writes the UID
            connectPacket.WriteMessage(publicKeyBase64);        // Writes the Base64 public key

            // Logs the packet structure for debugging
            ClientLogger.Log("Handshake packet structure:", LogLevel.Debug);
            ClientLogger.Log($"  → Username: {username}", LogLevel.Debug);
            ClientLogger.Log($"  → UID: {uid}", LogLevel.Debug);
            ClientLogger.Log($"  → PublicKeyBase64 fragment: {publicKeyBase64.Substring(0, 32)}…", LogLevel.Debug);

            // Sends the packet bytes and flushes to ensure immediate transmission
            NetworkStream stream = _client.GetStream();
            byte[] packetBytes = connectPacket.GetPacketBytes();
            stream.Write(packetBytes, 0, packetBytes.Length);
            stream.Flush();                                     // Ensures data is sent now

            // Logs success and spawns the packet reader
            ClientLogger.Log($"Initial connection packet sent — Username: {username}, UID: {uid}", LogLevel.Debug);
            Task.Run(() => ReadPackets());

            return true;
        }
        catch (Exception ex)
        {
            // Logs any error that occurs during handshake send
            ClientLogger.Log($"Failed to send initial connection packet: {ex.Message}", LogLevel.Error);
            return false;
        }
    }

    /// <summary>
    /// Sends a chat message to the server (opcode 5).  
    /// Validates connection state, LocalUser initialization, handshake completion, and key synchronization before encrypting.  
    /// When encryption is enabled and ready, it encrypts the message separately for each peer using its public key,  
    /// embeds senderUid and recipientUid in each packet, and logs every step.  
    /// When encryption is disabled or not ready, it falls back to a single plain-text broadcast packet.  
    /// </summary>
    /// <param name="message">The plain-text message to send.</param>
    public void SendMessageToServer(string message)
        {
            // Abort when the message is null, empty, or whitespace
            if (string.IsNullOrWhiteSpace(message))
                return;

            // Retrieve the ViewModel from MainWindow
            if (Application.Current.MainWindow is not MainWindow mainWindow
                || mainWindow.ViewModel is not MainViewModel viewModel)
            {
                ClientLogger.Log("ViewModel is null. Cannot send message.", LogLevel.Error);
                return;
            }

            // Abort when the TCP socket is not connected
            if (_client?.Connected != true)
            {
                ClientLogger.LogLocalized(LocalizationManager.GetString("ClientSocketNotConnected"), LogLevel.Error);
                return;
            }

            // Abort when LocalUser is not initialized or UID is missing
            var localUser = viewModel.LocalUser;
            if (localUser == null || string.IsNullOrWhiteSpace(localUser.UID))
            {
                ClientLogger.Log("LocalUser is not initialized. Cannot send message.", LogLevel.Error);
                return;
            }

            string senderUid = localUser.UID;

            // Encrypts per peer only when encryption is enabled, handshake is complete, and all keys are synchronized
            if (Properties.Settings.Default.UseEncryption
                && HandshakeCompleted
                && viewModel.IsEncryptionReady)
            {
                foreach (var kvp in viewModel.KnownPublicKeys)
                {
                    string peerUid = kvp.Key;
                    if (peerUid == senderUid)
                        continue;

                    // Encrypts the message using the peer’s public key
                    string encryptedPayload = EncryptionHelper.EncryptMessage(message, kvp.Value);
                    string payload = "[ENC]" + encryptedPayload;
                    ClientLogger.Log($"Encrypts message for {peerUid}.", LogLevel.Debug);

                    // Builds the packet: [OpCode][SenderUid][RecipientUid][Payload]
                    var packet = new PacketBuilder();
                    packet.WriteOpCode(5);
                    packet.WriteMessage(senderUid);
                    packet.WriteMessage(peerUid);
                    packet.WriteMessage(payload);

                    // Sends the encrypted packet to the server
                    _client.Client.Send(packet.GetPacketBytes());
                    ClientLogger.Log($"Sends encrypted packet for recipient {peerUid}.", LogLevel.Debug);
                }

                // Adds a local echo so the sender sees his own message immediately
                Application.Current.Dispatcher.Invoke(() =>
                {
                    viewModel.Messages.Add($"{localUser.Username}: {message}");
                });
            }
            else
            {
                // Warns if handshake is not complete before sending plain text
                if (!HandshakeCompleted)
                    ClientLogger.Log("Handshake not completed — sending plain message anyway.", LogLevel.Warn);

                ClientLogger.Log("Sends plain-text message.", LogLevel.Debug);

                // Builds the plain-text packet: [OpCode][SenderUid][Content]
                var packet = new PacketBuilder();
                packet.WriteOpCode(5);
                packet.WriteMessage(senderUid);
                packet.WriteMessage(message);

                // Sends the plain-text packet to the server
                _client.Client.Send(packet.GetPacketBytes());
                ClientLogger.Log("Sends plain-text packet.", LogLevel.Debug);
            }
        }

        /// <summary>
        /// Sends the client's public RSA key to the server for distribution to other connected clients.
        /// Builds a packet with OpCode 6, including the sender's UID and public key in Base64 format.
        /// Validates socket connectivity before dispatching, and logs each step for traceability.
        /// Allows transmission even if handshake is not completed, to support single-client scenarios.
        /// Returns true if the packet was sent successfully; false otherwise.
        /// </summary>
        /// <param name="uid">The UID of the sender.</param>
        /// <param name="publicKeyBase64">The public RSA key in Base64 format.</param>
        /// <returns>True if the packet was sent successfully; false if the client is not connected.</returns>
        public bool SendPublicKeyToServer(string uid, string publicKeyBase64)
        {
            // Validates socket connection before attempting to send
            if (_client?.Client == null || !_client.Connected)
            {
                ClientLogger.Log("Cannot send public key — client is not connected.", LogLevel.Error);
                return false;
            }

            // Logs handshake status for debugging
            if (!HandshakeCompleted)
            {
                ClientLogger.Log("Handshake not completed — sending public key anyway.", LogLevel.Warn);
            }

            // Builds the packet with required fields
            var packet = new PacketBuilder();
            packet.WriteOpCode(6); // Opcode for public key exchange
            packet.WriteMessage(uid);
            packet.WriteMessage(publicKeyBase64);

            ClientLogger.Log($"Sending public key — UID: {uid}, Key length: {publicKeyBase64.Length}", LogLevel.Debug);

            // Sends the packet to the server
            _client.Client.Send(packet.GetPacketBytes());

            ClientLogger.Log("Public key packet sent successfully.", LogLevel.Debug);
            return true;
        }
    }
}
