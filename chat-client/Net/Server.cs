/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 6th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.Net.IO;
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

        /// <summary>Provides the PacketReader used to read incoming packets; 
        /// initialized after connecting to the server.</summary>
        public PacketReader packetReader { get; private set; }


        /// <summary>Indicates whether the client is currently connected to the server.</summary>
        public bool IsConnected => _tcpClient?.Connected ?? false;

        /// <summary>Indicates whether the server has acknowledged the client's identity.</summary>
        public bool HandshakeCompleted { get; private set; } = false;

        // PUBLIC EVENTS

        // A new user joined (opcode 1)
        //   Parameters: uid, username, publicKey
        public event Action<string, string, string>? UserConnectedEvent;

        // A plain-text message arrived (opcode 5)
        //   Parameter: the fully formatted text
        public event Action<string>? PlainMessageReceivedEvent;

        /// Raised when the server delivers an encrypted message (opcode 11).
        /// Parameters: sender GUID and raw ciphertext bytes
        public event Action<Guid, byte[]>? EncryptedMessageReceivedEvent;

        // A peer’s public key arrived (opcode 6)
        //   Parameters: senderUid, publicKeyBase64
        public event Action<string, string>? PublicKeyReceivedEvent;

        // A user disconnected (opcode 10)
        //   Parameters: uid, username
        public event Action<string, string>? UserDisconnectedEvent;

        // Server-initiated disconnect (opcode 12)
        //   No parameters
        public event Action? DisconnectedByServerEvent;

        /// <summary>Gets the UID assigned to the local user.</summary>
        public Guid LocalUid { get; private set; }

        /// <summary>Gets the public key assigned to the local user.</summary>
        public string LocalPublicKey { get; private set; }


        private TcpClient _tcpClient;
 
        /// <summary>
        /// Instantiates a new Server.
        /// Creates a fresh TcpClient, resets the local UID to Guid.Empty,
        /// and initializes the public key string to an empty value.
        /// </summary>
        public Server()
        {
            _tcpClient = new TcpClient();
            
            LocalUid = Guid.Empty;
            LocalPublicKey = string.Empty;
        }

        /// <summary>
        /// Establishes a TCP connection to the chat server and begins packet processing.
        /// Validates the IP format, selects the correct port, and connects the client.
        /// Initializes the PacketReader for incoming data and starts the background read loop.
        /// Subscribes to PlainMessageReceivedEvent to echo messages to the console.
        /// Generates a unique UID and public key, sends the initial handshake packet,
        /// and returns the assigned identity on success or empty values on failure.
        /// </summary>
        /// <param name="username">The display name of the user initiating the connection.</param>
        /// <param name="IPAddressOfServer">
        /// The server’s IP address; defaults to localhost if null or empty.
        /// </param>
        /// <returns>
        /// A tuple containing the generated UID and RSA public key if successful;
        /// otherwise (Guid.Empty, string.Empty).
        /// </returns>
        public (Guid uid, string publicKeyBase64) ConnectToServer(
            string username,
            string IPAddressOfServer)
        {
            try
            {
                // Determines the target IP; defaults to localhost if none is provided
                string ipToConnect =
                    string.IsNullOrWhiteSpace(IPAddressOfServer)
                        ? "127.0.0.1"
                        : IPAddressOfServer;

                // Validates non-localhost IP format
                if (ipToConnect != "127.0.0.1"
                    && !System.Net.IPAddress.TryParse(ipToConnect, out _))
                {
                    throw new ArgumentException(
                        LocalizationManager.GetString("IPAddressInvalid"));
                }

                // Selects the port: uses custom if enabled, otherwise defaults to 7123
                int portToUse = Properties.Settings.Default.UseCustomPort
                    ? Properties.Settings.Default.CustomPortNumber
                    : 7123;

                // Establishes the TCP connection
                _tcpClient.Connect(ipToConnect, portToUse);
                ClientLogger.Log($"TCP connection established — IP: {ipToConnect}, Port: {portToUse}",
                    ClientLogLevel.Debug);

                // Initializes the packet reader over the live network stream
                var netStream = _tcpClient.GetStream();
                packetReader = new PacketReader(netStream);

                // Subscribes to plain-text message events to echo to the console
                PlainMessageReceivedEvent += message => Console.WriteLine(message);

                // Starts processing incoming packets on a background thread
                Task.Run(ReadPackets);

                // Generates a unique UID and retrieves the client's RSA public key
                Guid uid = Guid.NewGuid();
                string publicKeyBase64 = EncryptionHelper.PublicKeyBase64;
                ClientLogger.Log($"UID generated for handshake: {uid}", ClientLogLevel.Debug);
                ClientLogger.Log($"RSA public key generated: {publicKeyBase64}",
                    ClientLogLevel.Debug);

                // Sends the initial connection packet (username, UID, public key)
                if (!SendInitialConnectionPacket(username, uid, publicKeyBase64))
                {
                    throw new Exception(
                        "Failed to send initial connection packet.");
                }

                // Stores local identity values for future reference
                LocalUid = uid;
                LocalPublicKey = publicKeyBase64;

                return (uid, publicKeyBase64);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"[ERROR] Connection failed: {ex.Message}",
                    ClientLogLevel.Error);
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
                if (_tcpClient != null && _tcpClient.Connected)
                {
                    _tcpClient.Close();
                }

                // Prepares for future reconnection
                _tcpClient = new TcpClient();
            }
            catch (Exception ex)
            {
                // Log the error silently without interrupting the user
                ClientLogger.Log($"Disconnect failed: {ex.Message}", ClientLogLevel.Error);
            }
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
        /// Reads and processes all incoming packets from the server on a background thread.
        /// Secures a reference to the MainViewModel on the UI thread, then loops until
        /// the TCP client disconnects. For each packet:
        ///  - Reads the opcode byte.
        ///  - Reads the expected payload fields.
        ///  - Formats or decrypts data as needed.
        ///  - Calls the corresponding MainViewModel handler.
        /// Exits cleanly on I/O failure and logs all other exceptions.
        /// </summary>
        private void ReadPackets()
        {
            // Captures the ViewModel reference on the UI thread to avoid cross-thread errors
            MainViewModel viewModel = null!;
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow)
                    viewModel = mainWindow.ViewModel;
            });

            // If we couldn’t get the ViewModel, exits immediately
            if (viewModel == null)
                return;

            // Continuously reads from the network until the client disconnects
            while (_tcpClient.Connected)
            {
                try
                {
                    // Reads the 4-byte length prefix (network order)
                    int bodyLength = packetReader.ReadInt32NetworkOrder();
                    if (bodyLength <= 0)
                    {
                        ClientLogger.Log($"Invalid packet length: {bodyLength}", ClientLogLevel.Warn);
                        continue;
                    }

                    // Reads exactly bodyLength bytes
                    byte[] body = packetReader.ReadExact(bodyLength);

                    // Parses the body using a temporary PacketReader on a MemoryStream
                    using var ms = new MemoryStream(body);
                    PacketReader framedReader = new PacketReader(ms); 

                    // Reads the opcode from the framed payload
                    ClientPacketOpCode opcode = (ClientPacketOpCode)framedReader.ReadByte();

                    // Switches using framedReader instead of packetReader
                    switch (opcode)
                    {
                        case ClientPacketOpCode.ConnectionBroadcast:
                            Guid newUid = framedReader.ReadUid();
                            string newName = framedReader.ReadString();
                            string newPubKey = framedReader.ReadString();
                            HandshakeCompleted = true;
                            viewModel.OnUserConnected(newUid.ToString(), newName, newPubKey);
                            break;

                        case ClientPacketOpCode.PlainMessage:
                            Guid senderUid = framedReader.ReadUid();
                            _ = framedReader.ReadUid(); // discard recipient
                            string plainText = framedReader.ReadString();
                            viewModel.OnPlainMessageReceived(plainText);
                            break;

                        case ClientPacketOpCode.EncryptedMessage:
                            Guid sender = framedReader.ReadUid();
                            int cipherLen = framedReader.ReadInt32NetworkOrder();
                            byte[] cipher = framedReader.ReadExact(cipherLen);
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                EncryptedMessageReceivedEvent?.Invoke(sender, cipher);
                            });
                            break;

                        case ClientPacketOpCode.PublicKeyResponse:
                            Guid keyUid = framedReader.ReadUid();
                            string keyBase64 = framedReader.ReadString();
                            viewModel.OnPublicKeyReceived(keyUid.ToString(), keyBase64);
                            break;

                        case ClientPacketOpCode.DisconnectNotify:
                            Guid discUid = framedReader.ReadUid();
                            string discName = framedReader.ReadString();
                            viewModel.OnUserDisconnected(discUid.ToString(), discName);
                            break;

                        case ClientPacketOpCode.DisconnectClient:
                            viewModel.OnDisconnectedByServer();
                            break;

                        default:
                            byte raw = (byte)opcode;
                            ClientLogger.Log($"Unexpected byte 0x{raw:X2} inside framed packet", ClientLogLevel.Warn);
                            break;
                    }
                }
                catch (IOException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"ReadPackets error: {ex.Message}", ClientLogLevel.Error);
                }
            }
        }

        /// <summary>
        /// Sends a PublicKeyRequest packet to the server to retrieve all known public keys.
        /// Writes the PublicKeyRequest opcode followed by this client’s UID,
        /// flushes the stream to guarantee delivery,
        /// and logs the action for traceability.
        /// </summary>
        public void RequestAllPublicKeysFromServer()
        {
            // Builds the request packet: opcode + sender UID
            var packetBuilder = new PacketBuilder();
            packetBuilder.WriteOpCode((byte)ClientPacketOpCode.PublicKeyRequest);
            packetBuilder.WriteUid(LocalUid);

            // Sends the packet over the network stream and flushes immediately
            NetworkStream stream = _tcpClient.GetStream();
            byte[] payload = packetBuilder.GetPacketBytes();
            stream.Write(payload, 0, payload.Length);
            stream.Flush();

            // Logs the sync request with this client's UID
            ClientLogger.Log($"Public key sync request sent — UID: {LocalUid}",
                ClientLogLevel.Debug);
        }

        /// <summary>
        /// Sends a PublicKeyRequest packet to retrieve a peer’s public key.
        /// </summary>
        /// <param name="targetUid">The GUID of the peer whose key is requested.</param>
        private void RequestPeerPublicKey(Guid targetUid)
        {
            try
            {
                // Builds the request: opcode + your UID + target UID
                var packetBuilder = new PacketBuilder();
                packetBuilder.WriteOpCode((byte)ClientPacketOpCode.PublicKeyRequest);
                packetBuilder.WriteUid(LocalUid);
                packetBuilder.WriteUid(targetUid);

                // Sends it over the existing TCP connection
                NetworkStream stream = _tcpClient.GetStream();
                byte[] payload = packetBuilder.GetPacketBytes();
                stream.Write(payload, 0, payload.Length);
                stream.Flush();

                ClientLogger.Log($"Requested public key for {targetUid}.",
                    ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Key request for {targetUid} failed: {ex.Message}",
                    ClientLogLevel.Error);
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
        /// Encrypts the given plaintext and sends it securely to each recipient.
        /// Validates input and user context, handles solo mode, requests missing keys,
        /// builds and dispatches encrypted‐message packets, and tracks send success.
        /// </summary>
        /// <param name="plainText">The text to encrypt and send.</param>
        public bool SendEncryptedMessageToServer(string plainText)
        {
            // Prevents sending empty or whitespace‐only messages
            if (string.IsNullOrWhiteSpace(plainText))
                return false;

            // Retrieves main window and its view model
            if (Application.Current.MainWindow is not MainWindow mainWindow ||
                mainWindow.ViewModel is not MainViewModel viewModel ||
                viewModel.LocalUser == null)
            {
                return false;
            }

            // Determines sender UID
            string senderUid = viewModel.LocalUser.UID;

            // Builds recipient list: all other users or local user in solo mode
            var recipients = viewModel.Users
                .Where(u => u.UID != senderUid)
                .ToList();
            if (recipients.Count == 0)
            {
                // Solo mode: adds local user as recipient
                recipients.Add(viewModel.LocalUser);
            }

            bool messageSent = false;

            // Ensures thread‐safe access to the known‐keys dictionary
            lock (viewModel.KnownPublicKeys)
            {
                foreach (var recipient in recipients)
                {
                    string recipientUid = recipient.UID;
                    string publicKeyBase64;

                    if (recipientUid == senderUid)
                    {
                        // Solo mode: uses own public key
                        publicKeyBase64 = viewModel.LocalUser.PublicKeyBase64;
                        if (string.IsNullOrWhiteSpace(publicKeyBase64))
                        {
                            ClientLogger.Log(
                                $"Cannot encrypt to self: missing local public key for UID {senderUid}",
                                ClientLogLevel.Error);
                            continue;
                        }
                    }
                    else
                    {
                        // Requests peer key if missing
                        if (!viewModel.CanEncryptMessageFor(recipientUid))
                        {
                            if (Guid.TryParse(recipientUid, out var peerGuid))
                                RequestPeerPublicKey(peerGuid);
                            else
                                ClientLogger.Log(
                                    $"Invalid recipient UID: {recipientUid}",
                                    ClientLogLevel.Error);

                            continue;
                        }

                        // Ensures server has our public key
                        if (!viewModel.HasSentKeyTo(recipientUid))
                        {
                            var localKey = viewModel.LocalUser.PublicKeyBase64;
                            if (string.IsNullOrWhiteSpace(localKey))
                                ClientLogger.Log(
                                    "Cannot send public key: LocalUser.PublicKeyBase64 is uninitialized.",
                                    ClientLogLevel.Warn);
                            else
                                viewModel._server.SendPublicKeyToServer(recipientUid, localKey);

                            viewModel.MarkKeyAsSentTo(recipientUid);
                        }

                        // Retrieves peer public key from dictionary
                        publicKeyBase64 = viewModel.KnownPublicKeys[recipientUid];
                    }

                    try
                    {
                        // Encrypts plaintext with the appropriate public key
                        string cipher = EncryptionHelper.EncryptMessage(plainText, publicKeyBase64);

                        // Builds and sends an encrypted‐message packet
                        var encryptedMessagePacket = new PacketBuilder();
                        encryptedMessagePacket.WriteOpCode((byte)ClientPacketOpCode.EncryptedMessage);
                        encryptedMessagePacket.WriteUid(Guid.Parse(senderUid));
                        encryptedMessagePacket.WriteUid(Guid.Parse(recipientUid));
                        encryptedMessagePacket.WriteString(cipher);

                        _tcpClient.Client.Send(encryptedMessagePacket.GetPacketBytes());
                        ClientLogger.Log(
                            $"Encrypted message sent to {recipientUid}.",
                            ClientLogLevel.Debug);

                        messageSent = true;
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log(
                            $"Failed to encrypt or send to {recipientUid}: {ex.Message}",
                            ClientLogLevel.Error);
                    }
                }
            }

            return messageSent;
        }

        /// <summary>
        /// Builds and sends a framed handshake packet (opcode 0) to the server.
        /// Writes a 4-byte network-order length prefix followed by the packet body,
        /// then starts the inbound packet reader. Returns true on success, false on failure.
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
                // Constructs the handshake packet body: opcode + username + uid + public key.
                var connectPacket = new PacketBuilder();
                connectPacket.WriteOpCode((byte)ClientPacketOpCode.Handshake); // Opcode 0 = handshake
                connectPacket.WriteString(username);
                connectPacket.WriteUid(uid);
                connectPacket.WriteString(publicKeyBase64);

                // Serializes the packet body (without framing).
                byte[] body = connectPacket.GetPacketBytes();

                // Prepares a 4-byte length prefix in network byte order (big-endian).
                int bodyLength = body.Length;
                byte[] lengthPrefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(bodyLength));

                // Sends the framed packet: first the 4-byte length, then the body.
                NetworkStream stream = _tcpClient.GetStream();
                stream.Write(lengthPrefix, 0, lengthPrefix.Length);
                stream.Write(body, 0, body.Length);
                stream.Flush();

                // Logs the successful send and starts the reader loop.
                ClientLogger.Log($"Initial connection packet sent — Username: {username}, UID: {uid}", ClientLogLevel.Debug);
                Task.Run(() => ReadPackets());

                return true;
            }
            catch (Exception ex)
            {
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
        /// Builds and sends a framed plain-text chat packet to the server.
        /// Packet body format: [opcode][senderUID][recipientUID=Empty][UTF8 payload].
        /// The body is prefixed with a 4-byte network-order length before transmission.
        /// Logs success/failure and echoes the message locally on success.
        /// </summary>
        public bool SendPlainMessageToServer(string message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return false;

            if (Application.Current.MainWindow is not MainWindow mainWindow ||
                mainWindow.ViewModel is not MainViewModel viewModel)
            {
                ClientLogger.Log("SendPlainMessageToServer failed: UI context is missing.", ClientLogLevel.Error);
                return false;
            }

            if (_tcpClient?.Connected != true)
            {
                var errorMessage = LocalizationManager.GetString("ClientSocketNotConnected");
                ClientLogger.Log($"SendPlainMessageToServer failed: {errorMessage}", ClientLogLevel.Error);
                return false;
            }

            var localUser = viewModel.LocalUser;
            if (localUser == null || string.IsNullOrWhiteSpace(localUser.UID))
            {
                ClientLogger.Log("SendPlainMessageToServer failed: Local user is not initialized.", ClientLogLevel.Error);
                return false;
            }

            string payload = message.Trim();

            try
            {
                // Builds the packet body (opcode + sender UID + recipient placeholder + message)
                var plainMessagePacket = new PacketBuilder();
                plainMessagePacket.WriteOpCode((byte)ClientPacketOpCode.PlainMessage);
                plainMessagePacket.WriteUid(Guid.Parse(localUser.UID));
                plainMessagePacket.WriteUid(Guid.Empty); // placeholder for broadcast recipient
                plainMessagePacket.WriteString(payload);

                // Serializes body and create a 4-byte network-order length prefix
                byte[] body = plainMessagePacket.GetPacketBytes();
                byte[] lengthPrefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(body.Length));

                // Sends framed packet: length prefix then body, using NetworkStream for reliable Write/Flush
                NetworkStream stream = _tcpClient.GetStream();
                stream.Write(lengthPrefix, 0, lengthPrefix.Length);
                stream.Write(body, 0, body.Length);
                stream.Flush();

                ClientLogger.Log($"Sent framed plain message len={body.Length} preview=\"{(payload.Length > 64 ? payload.Substring(0, 64) + "…" : payload)}\"", ClientLogLevel.Debug);

                // Echoes locally on UI thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    viewModel.Messages.Add($"{localUser.Username}: {payload}");
                });

                return true;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"SendPlainMessageToServer exception: {ex.Message}", ClientLogLevel.Error);

                Application.Current.Dispatcher.Invoke(() =>
                {
                    viewModel.Messages.Add(LocalizationManager.GetString("MessageSendingFailed"));
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
            if (_tcpClient?.Client == null || !_tcpClient.Connected)
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
            publicKeyPacket.WriteUid(Guid.Parse(uid));
            publicKeyPacket.WriteString(publicKeyBase64);

            ClientLogger.Log($"Sending public key — UID: {uid}, Key length: {publicKeyBase64.Length}", ClientLogLevel.Debug);

            // Sends the packet to the server
            _tcpClient.Client.Send(publicKeyPacket.GetPacketBytes());

            ClientLogger.Log("Public key packet sent successfully.", ClientLogLevel.Debug);
            return true;
        }
    }
}
