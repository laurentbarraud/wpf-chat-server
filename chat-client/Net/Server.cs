/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 26th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
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
    /// </summary>
    public class Server
    {
        /// <summary>Used to build outgoing packets. Never null.</summary>
        public PacketBuilder packetBuilder { get; } = new PacketBuilder();

        /// <summary>Provides the PacketReader used to read incoming packets; initialized after establishing the connection.</summary>
        public PacketReader packetReader { get; private set; } = null!;

        /// <summary>Indicates whether the client is currently connected to the server.</summary>
        public bool IsConnected => _client?.Connected ?? false;

        /// <summary>Indicates whether the server has acknowledged the client's identity.</summary>
        public bool HandshakeCompleted { get; private set; } = false;

        /// <summary>Triggered when a new user joins (opcode 1).</summary>
        public event Action? ConnectedEvent;

        /// <summary>Triggered when a plain‐text message is received (opcode 5).</summary>
        public event Action? PlainMessageReceivedEvent;

        /// <summary>Triggered when an encrypted message is received (opcode 11).</summary>
        public event Action? EncryptedMessageReceivedEvent;

        /// <summary>Triggered when a peer’s public key is received (opcode 8).</summary>
        public event Action? PublicKeyReceivedEvent;

        /// <summary>Triggered when a user disconnects (opcode 10).</summary>
        public event Action? UserDisconnectEvent;

        /// <summary>Triggered when the server instructs this client to disconnect (opcode 12).</summary>
        public event Action? ServerDisconnectedClientEvent;

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

                // Reinitializes the PacketReader on the live stream
                packetReader = new PacketReader(_client.GetStream());

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
                packetReader?.Dispose();

                // Disposes the packet builder if it exists
                packetBuilder?.Dispose();

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
        /// Reads packets in a continuous loop.
        /// Converts the first byte to ClientPacketOpCode.
        /// Invokes matching events per opcode.
        /// Exits loop on I/O failure.
        /// Logs all other exceptions.
        /// </summary>
        private void ReadPackets()
        {
            while (_client.Connected)
            {
                try
                {
                    // Reads one byte and casts it to the opcode enum
                    ClientPacketOpCode opcode = (ClientPacketOpCode)packetReader.ReadByte();

                    // Dispatches the event corresponding to the opcode
                    switch (opcode)
                    {
                        case ClientPacketOpCode.ConnectionBroadcast:
                            HandshakeCompleted = true;
                            ConnectedEvent?.Invoke();
                            break;
                        case ClientPacketOpCode.PlainMessage:
                            PlainMessageReceivedEvent?.Invoke();
                            break;
                        case ClientPacketOpCode.EncryptedMessage:
                            EncryptedMessageReceivedEvent?.Invoke();
                            break;
                        case ClientPacketOpCode.PublicKeyResponse:
                            PublicKeyReceivedEvent?.Invoke();
                            break;
                        case ClientPacketOpCode.DisconnectNotify:
                            UserDisconnectEvent?.Invoke();
                            break;
                        case ClientPacketOpCode.DisconnectClient:
                            ServerDisconnectedClientEvent?.Invoke();
                            break;
                        default:
                            ClientLogger.Log($"Unknown opcode received: {opcode}", ClientLogLevel.Warn);
                            break;
                    }
                }
                catch (IOException)
                {
                    // Stops reading when the network stream fails
                    break;
                }
                catch (Exception ex)
                {
                    // Logs unexpected errors without interrupting the loop
                    ClientLogger.Log($"ReadPackets error: {ex.Message}", ClientLogLevel.Error);
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
            // Casts the enum to byte and writes it directly
            requestOfPublicKeysPacket.Write((byte)ClientPacketOpCode.PublicKeyRequest);
            // Opcode for public key sync request
            requestOfPublicKeysPacket.WriteMessage(LocalUid.ToString());

            // Sends the packet to the server via the active socket stream
            _client.GetStream().Write(requestOfPublicKeysPacket.GetPacketBytes(), 0, requestOfPublicKeysPacket.GetPacketBytes().Length
            );

            ClientLogger.Log($"Public key sync request sent — UID: {LocalUid}", ClientLogLevel.Debug);
        }

        /// <summary>
        /// Sends a public key request to get a peer’s public key.
        /// </summary>
        private void RequestPeerPublicKey(string targetUid)
        {
            try
            {
                var requestPeerPublicKeyPacket = new PacketBuilder();
                requestPeerPublicKeyPacket.WriteOpCode((byte)ClientPacketOpCode.PublicKeyRequest);
                requestPeerPublicKeyPacket.WriteMessage(LocalUid.ToString());
                requestPeerPublicKeyPacket.WriteMessage(targetUid);
                _client.Client.Send(requestPeerPublicKeyPacket.GetPacketBytes());
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
        /// Validates input, user context, and encryption prerequisites.
        /// Requests missing public keys and performs key exchange as needed.
        /// Builds and sends encrypted‐message packets without throwing.
        /// Echoes the plain text locally on success or displays an error on failure.
        /// </summary>
        /// <param name="plainText">The text to encrypt and send.</param>
        public bool SendEncryptedMessageToServer(string plainText)
        {
            // Avoids sending null, empty, or whitespace‐only messages
            if (string.IsNullOrWhiteSpace(plainText))
                return false;

            // Attempts to get MainWindow and its ViewModel
            if (Application.Current.MainWindow is not MainWindow _mainWindow ||
                _mainWindow.ViewModel is not MainViewModel ViewModel ||
                ViewModel.LocalUser == null)
            {
                return false;
            }

            string senderUid = ViewModel.LocalUser.UID;
            bool anySent = false;

            // Locks KnownPublicKeys for thread‐safe access
            lock (ViewModel.KnownPublicKeys)
            {
                foreach (var peer in ViewModel.Users.Where(u => u.UID != senderUid))
                {
                    string recipientUid = peer.UID;

                    // Requests the peer’s public key if missing
                    if (!ViewModel.CanEncryptMessageFor(recipientUid))
                    {
                        RequestPeerPublicKey(recipientUid);
                        continue;
                    }

                    // Ensures the server has the local public key for this peer
                    if (!ViewModel.HasSentKeyTo(recipientUid))
                    {
                        string localKey = ViewModel.LocalUser.PublicKeyBase64;
                        if (string.IsNullOrWhiteSpace(localKey))
                        {
                            ClientLogger.Log(
                                "Cannot send public key: LocalUser.PublicKeyBase64 is not initialized.",
                                ClientLogLevel.Warn);
                        }
                        else
                        {
                            ViewModel._server.SendPublicKeyToServer(recipientUid, localKey);
                        }
                        ViewModel.MarkKeyAsSentTo(recipientUid);
                    }

                    try
                    {
                        // Encrypts the message for this peer
                        string cipher = EncryptionHelper.EncryptMessage(
                            plainText,
                            ViewModel.KnownPublicKeys[recipientUid]);

                        // Builds the encrypted‐message packet: opcode + sender + recipient + cipher
                        var encryptedMessagePacket = new PacketBuilder();
                        encryptedMessagePacket.WriteOpCode((byte)ClientPacketOpCode.EncryptedMessage);
                        encryptedMessagePacket.WriteMessage(senderUid);
                        encryptedMessagePacket.WriteMessage(recipientUid);
                        encryptedMessagePacket.WriteMessage(cipher);

                        // Sends the raw packet bytes to the server
                        _client.Client.Send(encryptedMessagePacket.GetPacketBytes());
                        ClientLogger.Log(
                            $"Encrypted message sent to {recipientUid}.",
                            ClientLogLevel.Debug);

                        anySent = true;
                    }
                    catch (Exception ex)
                    {
                        // Logs any encryption or send failures per recipient
                        ClientLogger.Log(
                            $"Failed to encrypt or send to {recipientUid}: {ex.Message}",
                            ClientLogLevel.Error);
                    }
                }
            }

            // Echoes the plain text locally if any packet was sent
            // Otherwise displays a localized error in chat
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (anySent)
                {
                    ViewModel.Messages.Add($"{ViewModel.LocalUser.Username}: {plainText}");
                }
                else
                {
                    ViewModel.Messages.Add(
                        LocalizationManager.GetString("MessageSendingFailed"));
                }
            });

            return anySent;
        }


        // Echoes the plain text locally if any packet was sent;
        // otherwise displays a localized error in the UI.
        Application.Current.Dispatcher.Invoke(() =>
            {
                if (anySent)
                {
                    ViewModel.Messages.Add(
                        $"{ViewModel.LocalUser.Username}: {plainText}");
                }
                else
                {
                    ViewModel.Messages.Add(
                        LocalizationManager.GetString(
                            "MessageSendingFailed"));
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
                connectPacket.WriteOpCode((byte)ClientPacketOpCode.Handshake); // Opcode 0 = new user connection
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
        public bool SendMessageToServer(string message)
            => Properties.Settings.Default.UseEncryption
               ? SendEncryptedMessageToServer(message)
               : SendPlainMessageToServer(message);

        /// <summary>
        /// Sends a clear‐text chat message to the server and echoes it in the UI.
        /// Validates input, UI context, connection state, and local user data.
        /// Builds and sends a plain‐text packet without throwing exceptions.
        /// Logs any failures and returns false on error.
        /// </summary>
        public bool SendPlainMessageToServer(string message)
        {
            // Avoids sending null, empty, or whitespace‐only messages
            if (string.IsNullOrWhiteSpace(message))
                return false;

            // Attempts to get MainWindow and its ViewModel
            if (Application.Current.MainWindow is not MainWindow _mainWindow ||
                _mainWindow.ViewModel is not MainViewModel ViewModel)
            {
                ClientLogger.Log(
                    "SendPlainMessageToServer failed: UI context missing.",
                    ClientLogLevel.Error);
                return false;
            }

            // Checks that the TCP client is connected before sending
            if (_client?.Connected != true)
            {
                string err = LocalizationManager.GetString("ClientSocketNotConnected");
                ClientLogger.Log(
                    $"SendPlainMessageToServer failed: {err}",
                    ClientLogLevel.Error);
                return false;
            }

            // Verifies that LocalUser and its UID are initialized
            var local = ViewModel.LocalUser;
            if (local == null || string.IsNullOrWhiteSpace(local.UID))
            {
                ClientLogger.Log(
                    "SendPlainMessageToServer failed: LocalUser not initialized.",
                    ClientLogLevel.Error);
                return false;
            }

            // Trims leading/trailing spaces from the message payload
            string payload = message.Trim();

            try
            {
                // Builds the packet: opcode + sender UID + message text
                var _plainMessagePacket = new PacketBuilder();
                _plainMessagePacket.WriteOpCode((byte)ClientPacketOpCode.PlainMessage);
                _plainMessagePacket.WriteMessage(local.UID);
                _plainMessagePacket.WriteMessage(payload);

                // Sends the raw packet bytes to the server
                _client.Client.Send(_plainMessagePacket.GetPacketBytes());
                ClientLogger.Log(
                    "Plain‐text packet sent.",
                    ClientLogLevel.Debug);

                // Echoes the message in the chat UI on the main thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    ViewModel.Messages.Add($"{local.Username}: {payload}");
                });

                return true;
            }
            catch (Exception ex)
            {
                // Logs the exception and displays a localized error in chat
                ClientLogger.Log(
                    $"SendPlainMessageToServer exception: {ex.Message}",
                    ClientLogLevel.Error);
                Application.Current.Dispatcher.Invoke(() =>
                {
                    ViewModel.Messages.Add(
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
            var publicKeyPacket = new PacketBuilder();
            publicKeyPacket.WriteOpCode((byte)ClientPacketOpCode.PublicKeyResponse);
            publicKeyPacket.WriteMessage(uid);
            publicKeyPacket.WriteMessage(publicKeyBase64);

            ClientLogger.Log($"Sending public key — UID: {uid}, Key length: {publicKeyBase64.Length}", ClientLogLevel.Debug);

            // Sends the packet to the server
            _client.Client.Send(publicKeyPacket.GetPacketBytes());

            ClientLogger.Log("Public key packet sent successfully.", ClientLogLevel.Debug);
            return true;
        }
    }
}
