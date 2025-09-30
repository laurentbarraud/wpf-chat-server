/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 30th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.MVVM.Model;
using chat_client.Net.IO;
using System.IO;
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

        // PUBLIC EVENTS

        // Model A: a new user joined (opcode 1)
        //   Parameters: uid, username, publicKey
        public event Action<string, string, string>? ConnectedEvent;

        // Model C: a plain-text message arrived (opcode 5)
        //   Parameter: the fully formatted text
        public event Action<string>? PlainMessageReceivedEvent;

        /// Model E: Raised when the server delivers an encrypted message (opcode 11).
        /// Parameter: the fully decrypted and formatted text
        public event Action<string>? EncryptedMessageReceivedEvent;

        // Model D: a peer’s public key arrived (opcode 6)
        //   Parameters: senderUid, publicKeyBase64
        public event Action<string, string>? PublicKeyReceivedEvent;

        // Model A: a user disconnected (opcode 10)
        //   Parameters: uid, username
        public event Action<string, string>? UserDisconnectedEvent;

        // Model F: server-initiated disconnect (opcode 12)
        //   No parameters
        public event Action? DisconnectedByServerEvent;

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
                _client.Connect(ipToConnect, portToUse);
                ClientLogger.ClientLog($"TCP connection established — IP: {ipToConnect}, Port: {portToUse}",
                    ClientLogLevel.Debug);

                // Initializes the packet reader over the live network stream
                packetReader = new PacketReader(_client.GetStream());

                // Subscribes to plain-text message events to echo to the console
                PlainMessageReceivedEvent += message => Console.WriteLine(message);

                // Starts processing incoming packets on a background thread
                Task.Run(ReadPackets);

                // Generates a unique UID and retrieves the client's RSA public key
                Guid uid = Guid.NewGuid();
                string publicKeyBase64 = EncryptionHelper.PublicKeyBase64;
                ClientLogger.ClientLog($"UID generated for handshake: {uid}", ClientLogLevel.Debug);
                ClientLogger.ClientLog($"RSA public key generated: {publicKeyBase64}",
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
                ClientLogger.ClientLog($"[ERROR] Connection failed: {ex.Message}",
                    ClientLogLevel.Error);
                return (Guid.Empty, string.Empty);
            }
        }

        /// <summary>
        /// Model E: Reads, decrypts and formats an encrypted chat packet (opcode 11),
        /// filters out messages not addressed to this client, and raises
        /// EncryptedMessageReceivedEvent with the ready-to-display string.
        /// </summary>
        private void DecryptMessageReceived()
        {
            try
            {
                // Read sender and recipient UIDs (16 bytes each)
                Guid senderUid = packetReader.ReadUid();
                Guid recipientUid = packetReader.ReadUid();

                // Ignore messages not addressed to this client (non‐broadcast)
                // Uses the server’s LocalUid (Guid) instead of a non‐existent LocalUser
                if (recipientUid != Guid.Empty
                    && recipientUid != LocalUid)
                {
                    return;
                }

                // Read and sanitize the Base64‐encoded ciphertext
                string encryptedBase64 = packetReader
                    .ReadString()
                    .Replace("\0", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();

                // Attempt decryption and fallback on localized error
                string decrypted;
                try
                {
                    decrypted = EncryptionHelper.DecryptMessage(encryptedBase64);
                }
                catch (Exception exDecrypt)
                {
                    ClientLogger.ClientLog($"Decryption error for sender {senderUid}: {exDecrypt.Message}",
                        ClientLogLevel.Error);
                    decrypted = LocalizationManager.GetString("DecryptionFailed");
                }

                // Format the display string; any further name‐resolution
                // is done in the ViewModel based on senderUid
                string messageToDisplay = $"{senderUid}: {decrypted}";

                // Raise the event with the fully formatted string
                EncryptedMessageReceivedEvent?.Invoke(messageToDisplay);
            }
            catch (Exception ex)
            {
                ClientLogger.ClientLog($"DecryptMessageReceived failed: {ex.Message}",
                    ClientLogLevel.Error);
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

                // PacketBuilder is not IDisposable and is declared readonly,
                // so we do nothing here. Any new packet can be built with
                // a fresh local PacketBuilder in send methods.

                // Prepares for future reconnection
                _client = new TcpClient();
            }
            catch (Exception ex)
            {
                // Log the error silently without interrupting the user
                ClientLogger.ClientLog($"Disconnect failed: {ex.Message}", ClientLogLevel.Error);
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
            // Capture the ViewModel reference on the UI thread to avoid cross-thread errors
            MainViewModel viewModel = null!;
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow)
                    viewModel = mainWindow.ViewModel;
            });

            // If we couldn’t get the ViewModel, bail out immediately
            if (viewModel == null)
                return;

            // Continuously read from the network until the client disconnects
            while (_client.Connected)
            {
                try
                {
                    // Read the next opcode byte and cast to our enum
                    ClientPacketOpCode opcode = (ClientPacketOpCode)packetReader.ReadByte();

                    switch (opcode)
                    {
                        case ClientPacketOpCode.ConnectionBroadcast:
                            // Model A: new user joined → (uid, username, publicKey)
                            Guid newUid = packetReader.ReadUid();
                            string newName = packetReader.ReadString();
                            string newPubKey = packetReader.ReadString();

                            HandshakeCompleted = true;
                            viewModel.UserConnected(
                                newUid.ToString(),
                                newName,
                                newPubKey);
                            break;

                        case ClientPacketOpCode.PlainMessage:
                            // Model C: plain-text message arrives → (senderUid, text)
                            (Guid plainUid, string plainText) =
                                packetReader.ReadPlainMessage();
                            viewModel.PlainMessageReceived(plainText);
                            break;

                        case ClientPacketOpCode.EncryptedMessage:
                            // Model E: encrypted message arrives → (senderUid, cipherBytes)
                            (Guid encUid, byte[] cipherBytes) =
                                packetReader.ReadEncryptedMessage();

                            // Convert raw bytes to Base64 and decrypt
                            string base64 = Convert.ToBase64String(cipherBytes);
                            string decrypted;
                            try
                            {
                                decrypted = EncryptionHelper.DecryptMessage(base64);
                            }
                            catch (Exception ex)
                            {
                                ClientLogger.ClientLog(
                                    $"Decryption error from {encUid}: {ex.Message}",
                                    ClientLogLevel.Error);
                                decrypted = LocalizationManager.GetString("DecryptionFailed");
                            }

                            // Prepend sender UID and dispatch
                            string formatted = $"{encUid}: {decrypted}";
                            viewModel.EncryptedMessageReceived(formatted);
                            break;

                        case ClientPacketOpCode.PublicKeyResponse:
                            // Model D: peer public key arrives → (senderUid, publicKeyBase64)
                            (Guid keyUid, string keyBase64) =
                                packetReader.ReadPublicKeyResponse();
                            viewModel.PublicKeyReceived(
                                keyUid.ToString(),
                                keyBase64);
                            break;

                        case ClientPacketOpCode.DisconnectNotify:
                            // Model A: user disconnected → (uid, username)
                            (Guid discUid, string discName) =
                                packetReader.ReadUserDisconnected();
                            viewModel.UserDisconnected(
                                discUid.ToString(),
                                discName);
                            break;

                        case ClientPacketOpCode.DisconnectClient:
                            // Model F: server tells us to disconnect → no payload
                            packetReader.ReadServerDisconnect(); // read and discard
                            viewModel.ServerDisconnectedClient();
                            break;

                        default:
                            // Log unknown opcodes for future troubleshooting
                            ClientLogger.ClientLog(
                                $"Unknown opcode received: {opcode}",
                                ClientLogLevel.Warn);
                            break;
                    }
                }
                catch (IOException)
                {
                    // Connection dropped or stream closed—exit loop gracefully
                    break;
                }
                catch (Exception ex)
                {
                    // Log any unexpected error but keep processing subsequent packets
                    ClientLogger.ClientLog(
                        $"ReadPackets error: {ex.Message}",
                        ClientLogLevel.Error);
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
            NetworkStream stream = _client.GetStream();
            byte[] payload = packetBuilder.GetPacketBytes();
            stream.Write(payload, 0, payload.Length);
            stream.Flush();

            // Logs the sync request with this client's UID
            ClientLogger.ClientLog($"Public key sync request sent — UID: {LocalUid}",
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
                NetworkStream stream = _client.GetStream();
                byte[] payload = packetBuilder.GetPacketBytes();
                stream.Write(payload, 0, payload.Length);
                stream.Flush();

                ClientLogger.ClientLog(
                    $"Requested public key for {targetUid}.",
                    ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.ClientLog(
                    $"Key request for {targetUid} failed: {ex.Message}",
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
                ClientLogger.ClientLog("Cannot resend public key — UID or key is missing.", ClientLogLevel.Warn);
                return;
            }

            // Sends the public key to the server for redistribution
            SendPublicKeyToServer(LocalUid.ToString(), LocalPublicKey);
            ClientLogger.ClientLog("Public key resent manually — UID: " + LocalUid, ClientLogLevel.Debug);
        }

        /// <summary>
        /// Encrypts and sends a secure message to each recipient:
        ///   • Validates input and user context.
        ///   • Determines recipients: all other users or the local user in solo mode.
        ///   • Requests missing public keys and exchanges keys as needed (skip self in solo mode).
        ///   • Builds and dispatches encrypted‐message packets via the TCP client.
        ///   • Returns true if at least one packet was successfully sent.
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

            // Sender identifier
            string senderUid = viewModel.LocalUser.UID;

            // Builds recipient list (exclude self for multi‐party, include self for solo mode)
            var recipients = viewModel.Users
                .Where(u => u.UID != senderUid)
                .ToList();

            if (recipients.Count == 0)
            {
                // Solo mode: adds local user as recipient
                recipients.Add(viewModel.LocalUser);
            }

            bool messageSent = false;

            // Thread‐safe access to known keys
            lock (viewModel.KnownPublicKeys)
            {
                foreach (var recipient in recipients)
                {
                    string recipientUid = recipient.UID;

                    // Requests peer key if missing (skip for self in solo mode)
                    if (recipientUid != senderUid && !viewModel.CanEncryptMessageFor(recipientUid))
                    {
                        if (Guid.TryParse(recipientUid, out var peerGuid))
                            RequestPeerPublicKey(peerGuid);
                        else
                            ClientLogger.ClientLog($"Invalid recipient UID: {recipientUid}", ClientLogLevel.Error);

                        continue;
                    }

                    // Ensures server knows local public key (skip self)
                    if (recipientUid != senderUid && !viewModel.HasSentKeyTo(recipientUid))
                    {
                        var localKey = viewModel.LocalUser.PublicKeyBase64;
                        if (string.IsNullOrWhiteSpace(localKey))
                            ClientLogger.ClientLog(
                                "Cannot send public key: LocalUser.PublicKeyBase64 is uninitialized.",
                                ClientLogLevel.Warn);
                        else
                            viewModel._server.SendPublicKeyToServer(recipientUid, localKey);

                        viewModel.MarkKeyAsSentTo(recipientUid);
                    }

                    try
                    {
                        // Encrypts and sends packet
                        var cipher = EncryptionHelper.EncryptMessage(plainText, viewModel.KnownPublicKeys[recipientUid]);
                        var builder = new PacketBuilder();
                        builder.WriteOpCode((byte)ClientPacketOpCode.EncryptedMessage);
                        builder.WriteUid(Guid.Parse(senderUid));
                        builder.WriteUid(Guid.Parse(recipientUid));
                        builder.WriteString(cipher);

                        _client.Client.Send(builder.GetPacketBytes());
                        ClientLogger.ClientLog($"Encrypted message sent to {recipientUid}.", ClientLogLevel.Debug);

                        messageSent = true;
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.ClientLog(
                            $"Failed to encrypt or send to {recipientUid}: {ex.Message}",
                            ClientLogLevel.Error);
                    }
                }
            }

            return messageSent;
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

                connectPacket.WriteString(username);               // Writes the Username
                connectPacket.WriteUid(uid);                       // Writes the UID
                connectPacket.WriteString(publicKeyBase64);        // Writes the Base64 public key

                // Logs the packet structure for debugging
                ClientLogger.ClientLog("Handshake packet structure:", ClientLogLevel.Debug);
                ClientLogger.ClientLog($"  → Username: {username}", ClientLogLevel.Debug);
                ClientLogger.ClientLog($"  → UID: {uid}", ClientLogLevel.Debug);
                ClientLogger.ClientLog($"  → PublicKeyBase64 fragment: {publicKeyBase64.Substring(0, 32)}…", ClientLogLevel.Debug);

                // Sends the packet bytes and flushes to ensure immediate transmission
                NetworkStream stream = _client.GetStream();
                byte[] packetBytes = connectPacket.GetPacketBytes();
                stream.Write(packetBytes, 0, packetBytes.Length);
                stream.Flush();                                     // Ensures data is sent now

                // Logs success and spawns the packet reader
                ClientLogger.ClientLog($"Initial connection packet sent — Username: {username}, UID: {uid}", ClientLogLevel.Debug);
                Task.Run(() => ReadPackets());

                return true;
            }
            catch (Exception ex)
            {
                // Logs any error that occurs during handshake send
                ClientLogger.ClientLog($"Failed to send initial connection packet: {ex.Message}", ClientLogLevel.Error);
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
                ClientLogger.ClientLog(
                    "SendPlainMessageToServer failed: UI context missing.",
                    ClientLogLevel.Error);
                return false;
            }

            // Checks that the TCP client is connected before sending
            if (_client?.Connected != true)
            {
                string err = LocalizationManager.GetString("ClientSocketNotConnected");
                ClientLogger.ClientLog(
                    $"SendPlainMessageToServer failed: {err}",
                    ClientLogLevel.Error);
                return false;
            }

            // Verifies that LocalUser and its UID are initialized
            var local = ViewModel.LocalUser;
            if (local == null || string.IsNullOrWhiteSpace(local.UID))
            {
                ClientLogger.ClientLog(
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
                _plainMessagePacket.WriteUid(Guid.Parse(local.UID));    // replaced WriteMessage
                _plainMessagePacket.WriteString(payload);               // replaced WriteMessage

                // Sends the raw packet bytes to the server
                _client.Client.Send(_plainMessagePacket.GetPacketBytes());
                ClientLogger.ClientLog(
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
                ClientLogger.ClientLog(
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
                ClientLogger.ClientLog("Cannot send public key — client is not connected.", ClientLogLevel.Error);
                return false;
            }

            // Logs handshake status for debugging
            if (!HandshakeCompleted)
            {
                ClientLogger.ClientLog("Handshake not completed — sending public key anyway.", ClientLogLevel.Warn);
            }

            // Builds the packet with required fields
            var publicKeyPacket = new PacketBuilder();
            publicKeyPacket.WriteOpCode((byte)ClientPacketOpCode.PublicKeyResponse);
            publicKeyPacket.WriteUid(Guid.Parse(uid));
            publicKeyPacket.WriteString(publicKeyBase64);

            ClientLogger.ClientLog($"Sending public key — UID: {uid}, Key length: {publicKeyBase64.Length}", ClientLogLevel.Debug);

            // Sends the packet to the server
            _client.Client.Send(publicKeyPacket.GetPacketBytes());

            ClientLogger.ClientLog("Public key packet sent successfully.", ClientLogLevel.Debug);
            return true;
        }
    }
}
