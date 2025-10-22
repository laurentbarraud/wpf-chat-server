/// <file>Server.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 23th, 2025</date>

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
        public PacketReader packetReader { get; private set; } = null!;

        /// <summary>Indicates whether the client is currently connected to the server.</summary>
        public bool IsConnected => _tcpClient?.Connected ?? false;

        // PUBLIC EVENTS

        // Fired when a new connection is about to start reading packets.
        // Subscribers should reset their roster snapshot state.
        public event Action? ConnectionEstablished;

        // Fired when the connection is being terminated.
        // Subscribers should reset their roster snapshot state.
        public event Action? ConnectionTerminated;

        // A new user joined (opcode 1)
        //   Parameters: uid, username, publicKey
        public event Action<Guid, string, byte[]>? UserConnectedEvent;

        // A plain-text message arrived (opcode 5)
        //   Parameter: the fully formatted text
        public event Action<string, string>? PlainMessageReceivedEvent;

        /// Raised when the server delivers an encrypted message (opcode 11).
        /// Parameters: sender GUID and raw ciphertext bytes
        public event Action<Guid, byte[]>? EncryptedMessageReceivedEvent;

        // A peer’s public key arrived (opcode 6)
        //   Parameters: senderUid, publicKeyDer
        public event Action<Guid, byte[]>? PublicKeyReceivedEvent;
   
        // A user disconnected (opcode 10)
        //   Parameters: uid, username
        public event Action<Guid, string>? UserDisconnectedEvent;

        // Server-initiated disconnect (opcode 12)
        //   No parameters
        public event Action? DisconnectedByServerEvent;

        /// <summary>Gets the UID assigned to the local user.</summary>
        public Guid LocalUid { get; private set; }

        /// <summary>Gets the public key assigned to the local user.</summary>
        public byte[] LocalPublicKey { get; private set; }


        private TcpClient _tcpClient;

        /// <summary>
        /// Instantiates a new Server.
        /// Creates a fresh TcpClient, resets the local UID to Guid.Empty,
        /// and initializes the local public key to an empty byte array.
        /// </summary>
        public Server()
        {
            _tcpClient = new TcpClient();

            LocalUid = Guid.Empty;
            LocalPublicKey = Array.Empty<byte>();
        }

        /// <summary>
        /// Establishes a TCP connection to the server, creates a unique identity,
        /// sends a framed handshake packet (username, UID, RSA key), and then
        /// starts the packet-reading loop on a background thread.
        /// </summary>
        public (Guid uid, byte[] publicKeyDer) ConnectToServer(string username,
            string IPAddressOfServer)
        {
            try
            {
                // Determines target IP (default to localhost)
                string ipToConnect = string.IsNullOrWhiteSpace(IPAddressOfServer)
                    ? "127.0.0.1" : IPAddressOfServer;

                // Validates non-localhost address
                if (ipToConnect != "127.0.0.1" && !System.Net.IPAddress.TryParse(ipToConnect, out _))
                {
                    throw new ArgumentException(LocalizationManager.GetString("IPAddressInvalid"));
                }

                // Chooses port: custom if enabled, otherwise default 7123
                int port = Properties.Settings.Default.UseCustomPort
                    ? Properties.Settings.Default.CustomPortNumber
                    : 7123;

                // Connects to the server
                _tcpClient.Connect(ipToConnect, port);
                ClientLogger.Log($"TCP connection established — IP: {ipToConnect}, Port: {port}",
                    ClientLogLevel.Debug);

                // Prepares to read incoming packets
                packetReader = new PacketReader(_tcpClient.GetStream());

                // Generates UID and public key
                Guid uid = Guid.NewGuid();
                byte[] publicKeyDer = EncryptionHelper.PublicKeyDer;

                // Stores locally for ReadPackets logic
                LocalUid = uid;
                LocalPublicKey = publicKeyDer;

                // Notify that a fresh connection is established
                ConnectionEstablished?.Invoke();

                // Starts the background reader
                Task.Run(() => ReadPackets());

                // Sends the framed handshake (username, uid, publicKey)
                if (!SendInitialConnectionPacket(username, uid, publicKeyDer))
                    throw new InvalidOperationException("Failed to send initial handshake.");

                return (uid, publicKeyDer);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"[ERROR] Connection failed: {ex.Message}",
                    ClientLogLevel.Error);
                return (Guid.Empty, Array.Empty<byte>());
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
                // Closes the TCP connection if it's still active
                if (_tcpClient != null && _tcpClient.Connected)
                {
                    _tcpClient.Close();
                }

                // Prepares for future reconnection
                _tcpClient = new TcpClient();

                // Notifies that the connection is terminated
                ConnectionTerminated?.Invoke();
            }
            catch (Exception ex)
            {
                // Logs the error silently without interrupting the user
                ClientLogger.Log($"Disconnect failed: {ex.Message}", ClientLogLevel.Error);
            }
        }

        /// <summary> 
        /// Returns all known public RSA keys for connected users. 
        /// Filters out users with empty UID or missing public key bytes 
        /// and returns a Dictionary keyed by Guid with DER byte[] values. 
        /// A Dictionary is a collection of key/value pairs that allows 
        /// fast lookup of a value by its unique key; here the key is the
        /// user’s Guid and the value is the user’s public key in DER format.
        /// Using a Dictionary makes it efficient to find a specific user’s
        /// public key when encrypting a message or verifying signatures.
        /// </summary>

        public static Dictionary<Guid, byte[]> GetAllKnownPublicKeys(MainViewModel viewModel)
        {
            // Returns an empty dictionary if viewModel or Users list is null
            if (viewModel?.Users == null)
                return new Dictionary<Guid, byte[]>();

            return viewModel.Users
                // Uses lambdas functions : short parameter names like usr are generic.
                // This filters out users with uninitialized UID or empty public key.
                .Where(usr => usr.UID != Guid.Empty && usr.PublicKeyDer != null && usr.PublicKeyDer.Length > 0)
                // Project to Guid -> byte[] dictionary
                .ToDictionary(usr => usr.UID, usr => usr.PublicKeyDer!);
        }

        /// <summary>
        /// Frames a raw payload with a network-order length prefix for packet transmission.
        /// </summary>
        /// <param name="payload">Raw packet payload bytes.</param>
        /// <returns>Framed packet ready for network send.</returns>
        static byte[] Frame(byte[] payload)
        {
            using MemoryStream memoryStream = new MemoryStream();
            using BinaryWriter binaryWriter = new BinaryWriter(memoryStream);
            binaryWriter.Write(IPAddress.HostToNetworkOrder(payload.Length));
            binaryWriter.Write(payload);
            return memoryStream.ToArray();
        }

        /// <summary>
        /// Runs on a background thread to read all incoming framed packets  
        /// until the connection closes. Captures the MainViewModel on the UI thread,
        /// clears the user list on the first roster broadcast, and dispatches each
        /// opcode’s data to the ViewModel or events.
        /// </summary>
        private void ReadPackets()
        {
            // Captures the ViewModel instance on the UI thread
            MainViewModel viewModel = null!;
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mw)
                    viewModel = mw.ViewModel;
            });

            if (viewModel == null)
                return;

            while (true)
            {
                try
                {
                    // Reads the 4-byte length prefix (network order)
                    int length = packetReader.ReadInt32NetworkOrder();
                    if (length <= 0)
                    {
                        ClientLogger.Log($"Invalid packet length: {length}", ClientLogLevel.Warn);
                        continue;
                    }

                    // Reads the exact packet body
                    byte[] body = packetReader.ReadExact(length);

                    // Parses the framed payload
                    using var ms = new MemoryStream(body);
                    var reader = new PacketReader(ms);
                    var opcodeByte = reader.ReadByte();
                    var opcode = (ClientPacketOpCode)opcodeByte;

                    switch (opcode)
                    {
                        case ClientPacketOpCode.RosterBroadcast:
                            // Reads the number of users in this roster update (stored as a 32-bit network-order int)
                            int totalUsers = reader.ReadInt32NetworkOrder();

                            // Assembles the full roster list from the packet data using DER bytes for the public key
                            var rosterEntries = new List<(Guid UserId, string Username, byte[] PublicKeyDer)>();
                            for (int i = 0; i < totalUsers; i++)
                            {
                                // Extracts each user's unique ID, display name, and public key (binary DER)
                                Guid userId = reader.ReadUid();
                                string username = reader.ReadString();
                                byte[] publicKeyDer = reader.ReadBytesWithLength();

                                rosterEntries.Add((userId, username, publicKeyDer));
                            }

                            // Dispatches to the UI thread to apply the diff-based snapshot update
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                // DisplayRosterSnapshot expects byte[] PublicKeyDer
                                viewModel.DisplayRosterSnapshot(rosterEntries);
                            });
                            break;

                        case ClientPacketOpCode.PlainMessage:
                            // Plain-text message payload format:
                            //   [16-byte sender UID]
                            //   [16-byte recipient UID placeholder]
                            //   [4-byte text length][UTF-8 text bytes]
                            var (senderUid, message) = reader.ReadPlainMessage();

                            // Lookup sender’s display name
                            string senderName = viewModel.Users
                                .FirstOrDefault(u => u.UID == senderUid)?.Username
                                ?? senderUid.ToString();

                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnPlainMessageReceived(senderName, message));
                            break;

                        case ClientPacketOpCode.EncryptedMessage:
                            // Encrypted payload format:
                            //   [16-byte sender UID]
                            //   [16-byte recipient UID]
                            //   [4-byte ciphertext length][raw ciphertext bytes]
                            var (encSenderUid, cipherBytes) = reader.ReadEncryptedMessage();

                            string encSenderName = viewModel.Users
                                .FirstOrDefault(u => u.UID == encSenderUid)?.Username
                                ?? encSenderUid.ToString();

                            // Decrypts using the byte[] overload
                            string plainText = EncryptionHelper.DecryptMessageFromBytes(cipherBytes);

                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnPlainMessageReceived(encSenderName, plainText));
                            break;

                        case ClientPacketOpCode.PublicKeyResponse:
                            // PublicKeyResponse payload:
                            //   [16-byte origin UID]
                            //   [4-byte string length][UTF-8 bytes of DER public key]
                            //   [16-byte requester UID]
                            var (originUid, keyDer) = reader.ReadPublicKeyResponse();
                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnPublicKeyReceived(originUid, keyDer));
                            break;

                        case ClientPacketOpCode.DisconnectNotify:
                            // Reads a framed DisconnectNotify:
                            //   [16-byte UID][4-byte string length][UTF-8 username bytes]
                            var (discUid, discName) = reader.ReadUserDisconnected();
                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnUserDisconnected(discUid, discName));
                            break;

                        // Reads a framed ForceDisconnectClient packet and invokes the server-initiated disconnect handler
                        case ClientPacketOpCode.ForceDisconnectClient:
                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnDisconnectedByServer());
                            return;

                        default:
                            ClientLogger.Log($"Unexpected opcode 0x{opcodeByte:X2} in framed packet",
                                ClientLogLevel.Warn);
                            break;
                    }
                }
                catch (IOException)
                {
                    viewModel.OnDisconnectedByServer();
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"ReadPackets error: {ex.Message}", ClientLogLevel.Error);
                    viewModel.OnDisconnectedByServer();
                }
            }
        }

        /// <summary>
        /// Sends a PublicKeyRequest packet to the server to retrieve all known public keys.
        /// Writes the PublicKeyRequest opcode followed by this client’s UID,
        /// flushes the stream to guarantee delivery,
        /// and logs the action for traceability.
        /// </summary>
        public void SendRequestAllPublicKeysFromServer()
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
        /// Sends a framed DisconnectNotify packet to the server
        /// to announce a clean disconnect.
        /// Packet layout:
        ///   [4-byte big-endian length prefix]
        ///   [1-byte opcode: DisconnectNotify]
        ///   [16-byte UID of the disconnecting client]
        /// </summary>
        public void SendDisconnectNotifyToServer()
        {
            try
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ClientPacketOpCode.DisconnectNotify);
                builder.WriteUid(LocalUid);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                _tcpClient.Client.Send(framedPacket);
                ClientLogger.Log($"Sent DisconnectNotify for {LocalUid}", ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"DisconnectNotify failed: {ex.Message}", ClientLogLevel.Warn);
            }
        }

        /// <summary>
        /// Encrypts and sends a plaintext to selected recipients, handling missing keys and solo mode.
        /// • Validate input and UI context.
        /// • Build recipient list (other users or self in solo mode).
        /// • Lock KnownPublicKeys for thread-safe access.
        /// • For each recipient determine or request their DER public key.
        /// • Ensure server has our public key when needed.
        /// • Encrypt plaintext to raw bytes with recipient's DER key using RSA-OAEP-SHA256.
        /// • If ciphertext non-empty, frame and send an EncryptedMessage packet over the socket.
        /// • Log per-recipient errors and continue; return true if at least one send succeeded.
        /// </summary>
        /// <param name="plainText">The text to encrypt and send.</param>
        /// <returns>True if the message was successfully sent; otherwise false.</returns>
        public bool SendEncryptedMessageToServer(string plainText)
        {
            // Prevents sending empty or whitespace-only messages
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
            Guid senderUid = viewModel.LocalUser.UID;

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

            // Ensures thread-safe access to the known-keys dictionary
            lock (viewModel.KnownPublicKeys)
            {
                foreach (var recipient in recipients)
                {
                    Guid recipientUid = recipient.UID;
                    byte[] publicKeyDer;

                    if (recipientUid == senderUid)
                    {
                        // Solo mode: uses own public key
                        publicKeyDer = viewModel.LocalUser.PublicKeyDer ?? Array.Empty<byte>();
                        if (publicKeyDer.Length == 0)
                        {
                            ClientLogger.Log($"Cannot encrypt to self: missing local public key for UID {senderUid}",
                                ClientLogLevel.Error);
                            continue;
                        }
                    }
                    else
                    {
                        // Requests peer key if missing
                        if (!viewModel.CanEncryptMessageFor(recipientUid))
                        {
                            SendRequestToPeerForPublicKey(recipientUid);
                            continue;
                        }

                        // Ensures server has our public key
                        if (!viewModel.HasSentKeyTo(recipientUid))
                        {
                            var localKey = viewModel.LocalUser.PublicKeyDer ?? Array.Empty<byte>();
                            if (localKey.Length == 0)
                            {
                                ClientLogger.Log("Cannot send public key: LocalUser.PublicKeyDer is uninitialized.",
                                    ClientLogLevel.Warn);
                            }
                            else
                            {
                                // Send our public key to the server for distribution; sender is our local UID
                                viewModel._server.SendPublicKeyToServer(viewModel.LocalUser.UID, localKey);
                            }

                            viewModel.MarkKeyAsSentTo(recipientUid);
                        }

                        // Retrieves peer public key from dictionary
                        if (!viewModel.KnownPublicKeys.TryGetValue(recipientUid, out byte[]? peerPublicKey) || peerPublicKey == null || peerPublicKey.Length == 0)
                        {
                            ClientLogger.Log($"Missing public key for recipient {recipientUid} after sync attempt.", ClientLogLevel.Warn);
                            continue;
                        }
                        publicKeyDer = peerPublicKey; // peerPublicKey is now non-null and non-empty
                    }

                    try
                    {
                        // Encrypts plaintext to raw ciphertext bytes using DER public key
                        byte[] cipherArray = EncryptionHelper.EncryptMessageToBytes(plainText, publicKeyDer);

                        // If encryption failed or produced no data, skips this recipient
                        if (cipherArray == null || cipherArray.Length == 0)
                        {
                            ClientLogger.Log($"Encryption produced empty ciphertext for recipient {recipientUid}.", ClientLogLevel.Warn);
                            continue;
                        }

                        // Builds and sends an encrypted-message packet
                        var encryptedMessagePacket = new PacketBuilder();
                        encryptedMessagePacket.WriteOpCode((byte)ClientPacketOpCode.EncryptedMessage);
                        encryptedMessagePacket.WriteUid(senderUid);
                        encryptedMessagePacket.WriteUid(recipientUid);
                        encryptedMessagePacket.WriteBytesWithLength(cipherArray);

                        _tcpClient.Client.Send(encryptedMessagePacket.GetPacketBytes());
                        ClientLogger.Log($"Encrypted message sent to {recipientUid}.", ClientLogLevel.Debug);

                        messageSent = true;
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"Failed to encrypt or send to {recipientUid}: {ex.Message}", ClientLogLevel.Error);
                    }
                }
            }

            return messageSent;
        }

        /// <summary>
        /// Builds and sends a framed handshake packet (opcode = Handshake) to the server via raw socket send.
        /// Packet format on the wire:
        ///   [4-byte big-endian length][1-byte opcode][username][UID][publicKeyDer length][publicKeyDer bytes]
        /// On success, generates the inbound ReadPackets loop on a background thread.
        /// </summary>
        /// <param name="username">The display name of the user.</param>
        /// <param name="uid">The unique identifier assigned to the client during connection.</param>
        /// <param name="publicKeyDer">The DER-encoded RSA public key bytes.</param>
        /// <returns>True if the handshake packet was sent and reader started; false otherwise.</returns>
        public bool SendInitialConnectionPacket(string username, Guid uid, byte[] publicKeyDer)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            try
            {
                // Builds the payload: opcode + username + UID + public key (as length-prefixed bytes)
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ClientPacketOpCode.Handshake);
                builder.WriteString(username);
                builder.WriteUid(uid);
                builder.WriteBytesWithLength(publicKeyDer);

                // Frames it with a 4-byte network-order length prefix
                byte[] payload = builder.GetPacketBytes();
                byte[] framed = Frame(payload);

                // Logs and sends via the raw socket API
                ClientLogger.Log($"Sending handshake packet — Username: {username}, UID: {uid}", ClientLogLevel.Debug);
                _tcpClient.Client.Send(framed);
                return true;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Failed to send handshake packet: {ex.Message}", ClientLogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// Builds and sends a framed plain-text chat packet to the server.
        /// Packet structure:
        ///   [4-byte big-endian length]
        ///   [1-byte opcode: PlainMessage]
        ///   [16-byte sender UID]
        ///   [16-byte recipient UID placeholder]
        ///   [4-byte message length][UTF-8 message bytes]
        /// </summary>
        /// <param name="message">The chat message to broadcast.</param>
        /// <returns>True if the packet was sent; false on error or invalid state.</returns>
        public bool SendPlainMessageToServer(string message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return false;

            if (_tcpClient?.Connected != true)
            {
                ClientLogger.Log("SendPlainMessageToServer failed: socket not connected.", ClientLogLevel.Error);
                return false;
            }

            if (Application.Current.MainWindow is not MainWindow mainWindow ||
                mainWindow.ViewModel is not MainViewModel viewModel ||
                viewModel.LocalUser == null)
            {
                ClientLogger.Log("SendPlainMessageToServer failed: Local user is not initialized.", ClientLogLevel.Error);
                return false;
            }

            // LocalUser.UID is a Guid now; use it directly and validate it's initialized
            Guid userUid = viewModel.LocalUser.UID;
            if (userUid == Guid.Empty)
            {
                ClientLogger.Log("SendPlainMessageToServer failed: LocalUser.UID is empty.", ClientLogLevel.Error);
                return false;
            }

            string trimmed = message.Trim();
            try
            {
                // Builds payload: opcode + sender UID + empty recipient UID + message
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ClientPacketOpCode.PlainMessage);
                builder.WriteUid(userUid);
                builder.WriteUid(Guid.Empty);
                builder.WriteString(trimmed);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);  // prepend 4-byte length

                string preview = trimmed.Length > 64
                    ? trimmed[..64] + "…"
                    : trimmed;
                ClientLogger.Log($"Sending plain message: \"{preview}\"", ClientLogLevel.Debug);

                _tcpClient.Client.Send(framedPacket);
                return true;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"SendPlainMessageToServer exception: {ex.Message}", ClientLogLevel.Error);
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
        public bool SendPublicKeyToServer(Guid targetUid, byte[] publicKeyDer)
        {
            // Validates socket connection before attempting to send
            if (_tcpClient?.Client == null || !_tcpClient.Connected)
            {
                ClientLogger.Log("Cannot send public key — client is not connected.", ClientLogLevel.Error);
                return false;
            }

            // Builds the packet with required fields
            var publicKeyPacket = new PacketBuilder();
            publicKeyPacket.WriteOpCode((byte)ClientPacketOpCode.PublicKeyResponse);
            publicKeyPacket.WriteUid(targetUid);
            publicKeyPacket.WriteBytesWithLength(publicKeyDer);

            ClientLogger.Log($"Sending public key — UID: {targetUid}, Key length: {publicKeyDer.Length}", ClientLogLevel.Debug);

            // Sends the packet to the server
            _tcpClient.Client.Send(publicKeyPacket.GetPacketBytes());

            ClientLogger.Log("Public key packet sent successfully.", ClientLogLevel.Debug);
            return true;
        }

        /// <summary>
        /// Builds and sends a PublicKeyRequest packet to the server.
        /// Packet structure:
        ///   [4-byte length prefix]
        ///   [1-byte opcode: PublicKeyRequest]
        ///   [16-byte requester UID]
        ///   [16-byte target UID]
        /// </summary>
        /// <param name="targetUid">UID of the peer whose key is requested.</param>
        public void SendRequestToPeerForPublicKey(Guid targetUid)
        {
            try
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ClientPacketOpCode.PublicKeyRequest);
                builder.WriteUid(LocalUid);
                builder.WriteUid(targetUid);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                _tcpClient.Client.Send(framedPacket);
                ClientLogger.Log($"Requested public key for {targetUid}.", ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Key request for {targetUid} failed: {ex.Message}", ClientLogLevel.Error);
            }
        }
    }
}
