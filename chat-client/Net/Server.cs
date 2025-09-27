/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 26th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.Net;
using chat_client.Net.IO;
using chat_server.Helpers;
using ChatClient.Helpers;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Windows;

namespace chat_client.Net
{
    /// <summary>
    /// Represents the client-side connection to the server.
    /// Manages packet construction, reading, and dispatching.
    /// Exposes events for connection, message reception, and disconnection.
    /// Handles encryption handshake and maintains local identity.
    /// </summary>
    public class Server
    {
        /// <summary>Used to build outgoing packets.</summary>
        public PacketBuilder _packetBuilder;

        /// <summary>Used to read incoming packets from the server stream.</summary>
        public PacketReader _packetReader;

        /// <summary>Indicates whether the client is currently connected to the server.</summary>
        public bool IsConnected => _client?.Connected ?? false;

        /// <summary>Indicates whether the server has acknowledged the client's identity.</summary>
        public bool HandshakeCompleted { get; private set; } = false;
        
        /// <summary>Triggered when a new user joins (opcode 1).</summary>
        public event Action ConnectedEvent;

        /// <summary>Triggered when a plain‐text message is received (opcode 5).</summary>
        public event Action PlainMessageReceivedEvent;

        /// <summary>Triggered when an encrypted message is received (opcode 11).</summary>
        public event Action EncryptedMessageReceivedEvent;

        /// <summary>Triggered when a peer’s public key is received (opcode 8).</summary>
        public event Action PublicKeyReceivedEvent;

        /// <summary>Triggered when a user disconnects (opcode 10).</summary>
        public event Action UserDisconnectEvent;

        /// <summary>Gets the UID assigned to the local user.</summary>
        public Guid LocalUid { get; private set; }

        /// <summary>Gets the public key assigned to the local user.</summary>
        public string LocalPublicKey { get; private set; }


        private TcpClient _client;
 
        /// <summary>
        /// Instantiates a new Server.
        /// Creates a fresh TcpClient, resets the local UID to Guid.Empty,
        /// and initializes the public key string to an empty value.
        /// </summary>
        public Server()
        {
            _client = new TcpClient();
            LocalUid = Guid.Empty;
            LocalPublicKey = string.Empty;
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
        /// <returns>
        /// A tuple containing the UID and public key if successful; otherwise (Guid.Empty, string.Empty).
        /// </returns>
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
                ClientLogger.Log($"TCP connection established — IP: {ipToConnect}, Port: {portToUse}", ClientLogLevel.Debug);

                // Initializes the packet reader from the network stream
                PacketReader _packetReader = new PacketReader(_client.GetStream());

                // Generates UID and retrieves the client's RSA public key for handshake
                Guid uid = Guid.NewGuid();
                string publicKeyBase64 = EncryptionHelper.PublicKeyBase64;

                ClientLogger.Log($"UID generated for handshake: {uid}", ClientLogLevel.Debug);
                ClientLogger.Log($"RSA public key generated: {publicKeyBase64}", ClientLogLevel.Debug);

                // Sends the initial connection packet and starts listening
                if (!SendInitialConnectionPacket(username, uid, publicKeyBase64))
                    throw new Exception("Failed to send initial connection packet.");

                // Stores UID and public key locally for reference
                LocalUid = uid;
                LocalPublicKey = publicKeyBase64;

                return (uid, publicKeyBase64);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"[ERROR] Connection failed: {ex.Message}", ClientLogLevel.Error);
                return (Guid.Empty, string.Empty);
            }
        }

        /// <summary>
        /// Safely closes the TCP connection and resets the client state.
        /// Can be called multiple times without causing errors.
        /// Disposes the packet reader and resets the TCP client for future reconnection.
        /// Logs any failure silently as an error.
        /// </summary>
        public void DisconnectFromServer()
        {
            try
            {
                // Close the TCP connection if it's still active
                if (_client != null && _client.Connected)
                {
                    _client.Close();
                }

                // Disposes the packet reader if it exists
                _packetReader?.Dispose();

                // Disposes the packet builder if it exists
                _packetBuilder?.Dispose();

                // Prepares for future reconnection
                _client = new TcpClient();
            }
            catch (Exception ex)
            {
                // Log the error silently without interrupting the user
                ClientLogger.Log($"Disconnect failed: {ex.Message}", ClientLogLevel.Error);
            }
        }

        public void EncryptedMessageReceived()
        {

        }

        /// <summary>
        /// Returns all known public RSA keys for connected users.
        /// Keys may include the caller's own key; filtering is done client-side.
        /// Filters out users with missing UID or public key.
        /// After checking, we tell the compiler that the values are safe to use.
        /// </summary>
        public static Dictionary<string, string> GetAllKnownPublicKeys(MainViewModel viewModel)
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
            while (_client.Connected)
            {
                try
                {
                    var opcode = _packetReader.ReadOpCode();
                    switch (opcode)
                    {
                        case ClientPacketOpCode.ConnectionBroadcast:
                            ConnectedEvent?.Invoke();
                            break;

                        case ClientPacketOpCode.PlainMessage:
                            // Reads the raw payload and raises the plain‐text event
                            string plain = _packetReader.ReadMessage();
                            PlainMessageReceivedEvent?.Invoke();
                            break;

                        case ClientPacketOpCode.EncryptedMessage:
                            try
                            {
                                // Raises the encrypted‐message received event
                                EncryptedMessageReceivedEvent?.Invoke();
                            }
                            catch (Exception ex)
                            {
                                ClientLogger.Log(
                                    $"[ERROR] {LocalizationManager.GetString("DecryptionFailed")}: {ex.Message}",
                                    ClientLogLevel.Error);
                            }
                            break;

                        case ClientPacketOpCode.PublicKeyResponse:
                            PublicKeyReceivedEvent?.Invoke();
                            break;

                        case ClientPacketOpCode.DisconnectNotify:
                            UserDisconnectEvent?.Invoke();
                            break;

                        default:
                            ClientLogger.Log($"Unknown opcode received: {opcode}", ClientLogLevel.Warn);
                            break;
                    }
                }
                catch (IOException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"[ERROR] ReadPackets error: {ex.Message}", ClientLogLevel.Error);
                }
            }
        }

        /// <summary>
        /// Sends a request to the server asking for all known public keys.
        /// This triggers a series of opcode 6 packets in response.
        /// </summary>
        public void RequestAllPublicKeysFromServer()
        {
            var requestOfPublicKeysPacket = new PacketBuilder();
            requestOfPublicKeysPacket.WriteOpCode(ClientPacketOpCode.KeyRequest); // Opcode for public key sync request
            requestOfPublicKeysPacket.WriteMessage(LocalUid.ToString());

            // Sends the packet to the server via the active socket stream
            _client.GetStream().Write(
                requestOfPublicKeysPacket.GetPacketBytes(),
                0,
                requestOfPublicKeysPacket.GetPacketBytes().Length
            );

            ClientLogger.Log($"Public key sync request sent — UID: {LocalUid.ToString()}", ClientLogLevel.Debug);
        }

        /// <summary>
        /// Sends a KeyRequest (opcode KeyRequest) to get a peer’s public key.
        /// </summary>
        private void RequestPeerPublicKey(string targetUid)
        {
            try
            {
                var pkt = new PacketBuilder();
                pkt.WriteOpCode(ClientPacketOpCode.KeyRequest);
                pkt.WriteMessage(LocalUid.ToString());
                pkt.WriteMessage(targetUid);
                _client.Client.Send(pkt.GetPacketBytes());
                ClientLogger.Log($"Requested public key for {targetUid}.", ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"KeyRequest {targetUid} failed: {ex.Message}", ClientLogLevel.Error);
            }
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
            if (LocalUid == Guid.Empty || string.IsNullOrEmpty(LocalPublicKey))
            {
                ClientLogger.Log("Cannot resend public key — UID or key is missing.", ClientLogLevel.Warn);
                return;
            }

            // Sends the public key to the server for redistribution
            SendPublicKeyToServer(LocalUid.ToString(), LocalPublicKey);
            ClientLogger.Log("Public key resent manually — UID: " + LocalUid, ClientLogLevel.Debug);
        }

        /// <summary>
        /// Encrypts and sends a secure message to each peer.  
        /// Checks encryption prerequisites, requests missing public keys,  
        /// encrypts payloads, handles errors, and echoes the plaintext locally  
        /// on success or displays a localized error on failure.
        /// </summary>
        /// <param name="plainText">The text to encrypt and send.</param>
        /// <returns>True if at least one encrypted packet was sent; false otherwise.</returns>
        public bool SendEncryptedMessageToServer(string plainText)
        {
            if (string.IsNullOrWhiteSpace(plainText))
                return false;

            // Retrieves view model and sender UID
            if (Application.Current.MainWindow is not MainWindow _mainWindow
                || _mainWindow._viewModel is not MainViewModel _viewModel
                || _viewModel.LocalUser == null)
            {
                return false;
            }

            string senderUid = _viewModel.LocalUser.UID;
            bool anySent = false;

            lock (_viewModel.KnownPublicKeys)
            {
                foreach (var peer in _viewModel.Users.Where(u => u.UID != senderUid))
                {
                    string recipientUid = peer.UID;

                    // Requests missing public key if encryption prerequisites are not met
                    if (!_viewModel.CanEncryptMessageFor(recipientUid))
                    {
                        RequestPeerPublicKey(recipientUid);
                        continue;
                    }

                    // Ensure local key has been sent to this peer once
                    if (!_viewModel.HasSentKeyTo(recipientUid))
                    {
                        // Before sending, ensure the local public key is non‐null/non‐empty
                        string localKey = _viewModel.LocalUser.PublicKeyBase64;
                        if (string.IsNullOrWhiteSpace(localKey))
                        {
                            ClientLogger.Log(
                                "Cannot send public key: LocalUser.PublicKeyBase64 is not initialized.",
                                ClientLogLevel.Warn);
                        }
                        else
                        {
                            _viewModel._server.SendPublicKeyToServer(recipientUid, localKey);
                        }

                        _viewModel.MarkKeyAsSentTo(recipientUid);
                    }

                    try
                    {
                        // Encrypt the message for the peer
                        string cipher = EncryptionHelper.EncryptMessage(
                            plainText,
                            _viewModel.KnownPublicKeys[recipientUid]);

                        // Build and send the encrypted‐message packet
                        var pkt = new PacketBuilder();
                        pkt.WriteOpCode(ClientPacketOpCode.EncryptedMessage);
                        pkt.WriteMessage(senderUid);
                        pkt.WriteMessage(recipientUid);
                        pkt.WriteMessage(cipher);
                        _client.Client.Send(pkt.GetPacketBytes());

                        ClientLogger.Log(
                            $"Encrypted message sent to {recipientUid}.",
                            ClientLogLevel.Debug);

                        anySent = true;
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log(
                            $"Failed to encrypt or send to {recipientUid}: {ex.Message}",
                            ClientLogLevel.Error);
                    }
                }
            }

            // Echo plaintext or show error in the UI
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (anySent)
                {
                    _viewModel.Messages.Add($"{_viewModel.LocalUser.Username}: {plainText}");
                }
                else
                {
                    _viewModel.Messages.Add(
                        LocalizationManager.GetString("MessageSendingFailed"));
                }
            });

            return anySent;
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
                connectPacket.WriteOpCode(ClientPacketOpCode.Handshake);                       // Opcode 0 = new user connection
                connectPacket.WriteMessage(username);               // Writes the Username
                connectPacket.WriteMessage(uid.ToString());         // Writes the UID
                connectPacket.WriteMessage(publicKeyBase64);        // Writes the Base64 public key

                // Logs the packet structure for debugging
                ClientLogger.Log("Handshake packet structure:", ClientLogLevel.Debug);
                ClientLogger.Log($"  → Username: {username}", ClientLogLevel.Debug);
                ClientLogger.Log($"  → UID: {uid}", ClientLogLevel.Debug);
                ClientLogger.Log($"  → PublicKeyBase64 fragment: {publicKeyBase64.Substring(0, 32)}…", ClientLogLevel.Debug);

                // Sends the packet bytes and flushes to ensure immediate transmission
                NetworkStream stream = _client.GetStream();
                byte[] packetBytes = connectPacket.GetPacketBytes();
                stream.Write(packetBytes, 0, packetBytes.Length);
                stream.Flush();                                     // Ensures data is sent now

                // Logs success and spawns the packet reader
                ClientLogger.Log($"Initial connection packet sent — Username: {username}, UID: {uid}", ClientLogLevel.Debug);
                Task.Run(() => ReadPackets());

                return true;
            }
            catch (Exception ex)
            {
                // Logs any error that occurs during handshake send
                ClientLogger.Log($"Failed to send initial connection packet: {ex.Message}", ClientLogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// Chooses between plain or encrypted send based on application UseEncryption setting.
        /// </summary>
        public bool SendMessageToServer(string text)
            => Properties.Settings.Default.UseEncryption
               ? SendEncryptedMessageToServer(text)
               : SendPlainMessageToServer(text);

        /// <summary>
        /// Sends a clear‐text chat message to the server and echoes it in the UI.
        /// This method safely handles empty or whitespace messages, connection state,
        /// and missing user data. It never throws: failures are logged and return false.
        /// Repeated calls with the same input have no unintended side effects.
        /// </summary>
        public bool SendPlainMessageToServer(string message)
        {
            // Avoids sending null, empty, or whitespace‐only messages.
            // Trim removes any leading or trailing spaces so " hello " → "hello".
            // It also turns messages of only spaces into an empty string.
            if (string.IsNullOrWhiteSpace(message))
                return false;

            // Attempts to get the main window and its view model.
            // If unavailable, we cannot display or tag this message.
            if (Application.Current.MainWindow is not MainWindow _mainWindow ||
                _mainWindow._viewModel is not MainViewModel _viewModel)
            {
                ClientLogger.Log("SendMessageToServer failed: UI context missing.", ClientLogLevel.Error);
                return false;
            }

            // Ensures the TCP connection is open before trying to send.
            if (_client?.Connected != true)
            {
                string err = LocalizationManager.GetString("ClientSocketNotConnected");
                ClientLogger.Log($"SendMessageToServer failed: {err}", ClientLogLevel.Error);
                return false;
            }

            // Makes sure the local user identity is set up correctly.
            var local = _viewModel.LocalUser;
            if (local == null || string.IsNullOrWhiteSpace(local.UID))
            {
                ClientLogger.Log("SendMessageToServer failed: LocalUser not initialized.", ClientLogLevel.Error);
                return false;
            }

            // Prepare trimmed text to avoid accidental leading/trailing spaces.
            string payload = message.Trim();

            try
            {
                // Build the packet: write opcode then sender UID and the message text.
                var _packetBuilder = new PacketBuilder();
                _packetBuilder.WriteOpCode(ClientPacketOpCode.PlainMessage);
                _packetBuilder.WriteMessage(local.UID);
                _packetBuilder.WriteMessage(payload);

                // Send the raw bytes over the network.
                _client.Client.Send(_packetBuilder.GetPacketBytes());
                ClientLogger.Log("Plain‐text packet sent.", ClientLogLevel.Debug);

                // Safely update the UI on the main thread: echo the message.
                Application.Current.Dispatcher.Invoke(() =>
                {
                    _viewModel.Messages.Add($"{local.Username}: {payload}");
                });

                return true;
            }
            catch (Exception ex)
            {
                // Catches any failure: logs it and pushes a localized error into chat.
                ClientLogger.Log($"SendMessageToServer exception: {ex.Message}", ClientLogLevel.Error);
                Application.Current.Dispatcher.Invoke(() =>
                {
                    _viewModel.Messages.Add(
                        LocalizationManager.GetString("MessageSendingFailed"));
                });
                return false;
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
                ClientLogger.Log("Cannot send public key — client is not connected.", ClientLogLevel.Error);
                return false;
            }

            // Logs handshake status for debugging
            if (!HandshakeCompleted)
            {
                ClientLogger.Log("Handshake not completed — sending public key anyway.", ClientLogLevel.Warn);
            }

            // Builds the packet with required fields
            var packet = new PacketBuilder();
            packet.WriteOpCode(6); // Opcode for public key exchange
            packet.WriteMessage(uid);
            packet.WriteMessage(publicKeyBase64);

            ClientLogger.Log($"Sending public key — UID: {uid}, Key length: {publicKeyBase64.Length}", ClientLogLevel.Debug);

            // Sends the packet to the server
            _client.Client.Send(packet.GetPacketBytes());

            ClientLogger.Log("Public key packet sent successfully.", ClientLogLevel.Debug);
            return true;
        }
    }
}
