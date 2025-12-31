/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 31th, 2025</date>

using System;
using chat_server.Helpers;
using chat_protocol.Net.IO;
using chat_protocol.Net;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace chat_server
{
    public class Program
    {
        // Holds the current connected client handlers
        static internal List<ServerConnectionHandler> Users = new List<ServerConnectionHandler>();

        // TCP listener that accepts incoming client connections
        static TcpListener Listener = null!;

        // Cancellation token source used to stop the accept loop and shutdown accepting new clients
        private static CancellationTokenSource _acceptCts = new CancellationTokenSource();

        // True when the server shutdown was initiated by Ctrl+C
        private static bool _exitByCtrlC;

        // Maps each connected user's UID to a per-connection SemaphoreSlim
        // used to serialize async writes to that user's NetworkStream.
        // Ensures only one async send runs at a time per client, preventing
        // interleaved writes that would corrupt length-prefixed framing.
        private static readonly ConcurrentDictionary<Guid, SemaphoreSlim> _sendSemaphores = new ConcurrentDictionary<Guid, SemaphoreSlim>();

        /// <summary>
        /// Entry point — server accept loop with simplified handshake.
        /// </summary>
        public static async Task Main(string[] args)
        {
            // Initializes localization based on system language.
            string uiLang = CultureInfo.CurrentCulture.TwoLetterISOLanguageName.Equals("fr", StringComparison.OrdinalIgnoreCase) ? "fr" : "en";
            LocalizationManager.Initialize(uiLang);

            // Ensures console supports UTF-8 output.
            Console.OutputEncoding = Encoding.UTF8;

            // Cancellation token for accept loop and background tasks.
            _acceptCts = new CancellationTokenSource();
            CancellationToken token = _acceptCts.Token;

            // Graceful Ctrl+C shutdown.
            Console.CancelKeyPress += (s, e) => 
            { 
                e.Cancel = true; _exitByCtrlC = true; 
                Listener?.Stop(); 
                _acceptCts.Cancel(); 
            };

            // Graceful shutdown on process exit.
            AppDomain.CurrentDomain.ProcessExit += (s, e) => 
            { 
                if (!_exitByCtrlC) 
                { 
                    Listener?.Stop(); _acceptCts.Cancel(); 
                } 
            };

            // Display banner and prompt for port.
            DisplayBanner();
            int port = GetPortFromUser();

            try
            {
                Users = new List<ServerConnectionHandler>();
                Listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
                Listener.Start();
                Console.WriteLine(string.Format(LocalizationManager.GetString("ServerStartedOnPort"), port));

                // Accept loop — exits when Listener.Stop() is called or token is cancelled.
                while (!token.IsCancellationRequested)
                {
                    TcpClient tcpClient;
                    try 
                    {
                        tcpClient = await Listener.AcceptTcpClientAsync().ConfigureAwait(false); 
                    }
                    catch (ObjectDisposedException) 
                    { 
                        break; 
                    }
                    catch 
                    { 
                        await Task.Delay(100, token).ConfigureAwait(false); continue; 
                    }

                    // Handles accepted client on background task.
                    _ = Task.Run(async () =>
                    {
                        ServerConnectionHandler? client = null;
                        try
                        {
                            var networkStream = tcpClient.GetStream();

                            // Read 4-byte big-endian header.
                            byte[] header = await PacketReader.ReadExactAsync(networkStream, 4, token).ConfigureAwait(false);
                            int payloadLength = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
                            if (payloadLength <= 0 || payloadLength > 65_536) { tcpClient.Close(); return; }

                            // Reads payload and parse handshake.
                            byte[] payload = await PacketReader.ReadExactAsync(networkStream, payloadLength, token).ConfigureAwait(false);
                            using var memoryStream = new MemoryStream(payload);
                            var reader = new PacketReader(memoryStream);

                            if ((chat_protocol.Net.PacketOpCode)await reader.ReadByteAsync(token).ConfigureAwait(false) != PacketOpCode.Handshake)
                            { 
                                tcpClient.Close(); return; 
                            }

                            string username = await reader.ReadStringAsync(token).ConfigureAwait(false);
                            Guid uid = await reader.ReadUidAsync(token).ConfigureAwait(false);

                            // Reads and validates the public key from the handshake payload (always present in protocol).
                            int publicKeyLength = await reader.ReadInt32NetworkOrderAsync(token).ConfigureAwait(false);
                            const int MaxPublicKeyLength = 65_536;
                            if (publicKeyLength < 0 || publicKeyLength > MaxPublicKeyLength) { tcpClient.Close(); return; }

                            byte[] publicKey = await PacketReader.ReadExactAsync(memoryStream, publicKeyLength, token).ConfigureAwait(false);

                            // Initializes client after handshake with the raw public key (can be empty).
                            client = new ServerConnectionHandler(tcpClient);
                            client.InitializeAfterHandshake(username, uid, publicKey, token);

                            // Removes any previous session using the same username
                            lock (Users)
                            {
                                Users.RemoveAll(u => u.Username == username); 
                            } 

                            // Adds client to roster and log localized connection.
                            lock (Users) 
                            { 
                                Users.Add(client); 
                            }
                            
                            ServerLogger.LogLocalized("ClientConnected", ServerLogLevel.Info, username);

                            // Sends HandshakeAck (framed).
                            var ack = new PacketBuilder();
                            ack.WriteOpCode((byte)PacketOpCode.HandshakeAck);
                            await SendFramedAsync(client, ack.GetPacketBytes(), token).ConfigureAwait(false);

                            // Broadcasts roster after ack so all clients get updated keys (empty keys included).
                            await BroadcastRosterAsync(token).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) 
                        { 
                            tcpClient.Close(); 
                        }
                        
                    }, token);
                }

                // Graceful shutdown once loop exits.
                await ShutdownAsync(token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nFailed to start server on port {port}: {ex.Message}");
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Removes the specified user from the server roster
        /// and broadcasts a framed DisconnectNotify packet to all remaining clients.
        /// Packet layout:
        ///   [4-byte big-endian length prefix]
        ///   [1-byte opcode: DisconnectNotify]
        ///   [16-byte UID of the disconnected user]
        ///   [4-byte string length][UTF-8 bytes of username]
        /// </summary>
        /// <param name="disconnectedUserId">UID of the client who disconnected.</param>
        public static async Task BroadcastDisconnectNotify(Guid disconnectedUserId, CancellationToken cancellationToken)
        {
            // Uses the provided Guid directly
            Guid disconnectedGuid = disconnectedUserId;

            /// <summary>
            /// FirstOrDefault returns a nullable Client if no match is found
            /// </summary>
            ServerConnectionHandler? goneUser = Users.FirstOrDefault(u => u.UID == disconnectedGuid);
            
            /// <summary>
            /// Safely guards the removal logic
            /// </summary>
            if (goneUser is not null)
            {
                lock (Users)
                {
                    Users.Remove(goneUser);
                }
            }

            // Snapshots current users
            var snapshotUsers = Users.ToList();

            // Chooses a safe username fallback:
            // uses disconnected GUID string when username is unavailable
            string username = string.IsNullOrWhiteSpace(goneUser?.Username)
                            ? "(unknown)"
                            : goneUser.Username;

            /// <summary>
            /// Builds the framed DisconnectNotify for each remaining client
            /// and sends it if their socket is connected.
            /// </summary>
            var sendTasks = new List<Task>();

            foreach (var listener in snapshotUsers)
            {
                if (!listener.ClientSocket.Connected)
                {
                    continue;
                }

                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)PacketOpCode.DisconnectNotify);
                builder.WriteUid(disconnectedGuid);
                builder.WriteString(username);

                byte[] payload = builder.GetPacketBytes();

                // Shows what the builder returned before sending
                ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

                // Creates a per-listener task that performs the send and preserves existing logging.
                var sendTask = Task.Run(async () =>
                {
                    try
                    {
                        await SendFramedAsync(listener, payload, cancellationToken).ConfigureAwait(false);
                        ServerLogger.LogLocalized("DisconnectNotifySuccess", ServerLogLevel.Debug,
                            listener.Username);
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("DisconnectNotifyFailed", ServerLogLevel.Warn,
                            listener.Username, ex.Message);
                    }
                }, cancellationToken);

                sendTasks.Add(sendTask);
            }

            // Awaits all sends; if cancellation requested this will observe it via the token passed to each send.
            try
            {
                await Task.WhenAll(sendTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                
            }

            ServerLogger.LogLocalized("UserDisconnected", ServerLogLevel.Info, username);
        }

        /// <summary>
        /// • Builds and sends a framed ForceDisconnectClient packet to every connected client  
        /// • Packet structure: [4-byte length][1-byte opcode][16-byte target UID]  
        /// • Forces each client to call its Disconnect sequence upon decoding  
        /// </summary>
        public static async Task BroadcastForceDisconnect(CancellationToken cancellationToken)
        {
            // Takes a snapshot to avoid collection-modified issues while iterating
            var listeners = Users.Where(usr => usr.ClientSocket.Connected).ToList();

            var sendTasks = new List<Task>(listeners.Count);

            foreach (var user in listeners)
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)PacketOpCode.ForceDisconnectClient);
                builder.WriteUid(user.UID);

                byte[] payload = builder.GetPacketBytes();

                // Shows what the builder returned before sending
                ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

                // Per-listener send task
                var sendTask = Task.Run(async () =>
                {
                    try
                    {
                        await SendFramedAsync(user, payload, cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("BroadcastForceDisconnectFailed",
                            ServerLogLevel.Warn, user.Username, ex.Message);
                    }
                }, cancellationToken);

                sendTasks.Add(sendTask);
            }

            try
            {
                await Task.WhenAll(sendTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            ServerLogger.LogLocalized("BroadcastForceDisconnectSuccess",
                ServerLogLevel.Debug, Users.Count.ToString());
        }

        /// <summary>
        /// Broadcasts the full roster of connected users to every client:
        /// • Snapshots current users to avoid concurrent modification.
        /// • Builds a RosterBroadcast packet containing per-user: UID, username, and raw DER public key (length-prefixed).
        /// • Frames each packet with a 4-byte length prefix for wire transport.
        /// • Sends framed packet to each recipient and logs success or failure.
        /// </summary>
        public static async Task BroadcastRosterAsync(CancellationToken cancellationToken = default)
        {
            ///<summary> Snapshots current users <summary>
            var snapshotUsers = Users.ToList();

            /// <summary> Builds the roster payload <summary>
            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)PacketOpCode.RosterBroadcast);

            /// <summary> Writes roster count as 4-byte big-endian Int32 </summary>
            builder.WriteInt32NetworkOrder(snapshotUsers.Count);

            foreach (var target in snapshotUsers)
            {
                builder.WriteUid(target.UID);
                builder.WriteString(target.Username);
                byte[] publicKeyInBytes = target.PublicKeyDer ?? Array.Empty<byte>();
                builder.WriteBytesWithLength(publicKeyInBytes);
            }

            byte[] payload = builder.GetPacketBytes();

            // Shows what the builder returned before sending
            ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

            /// <summary> Launches send tasks for all recipients </summary>
            var sendTasks = new List<Task>(snapshotUsers.Count);
            foreach (var recipient in snapshotUsers)
            {
                var task = Task.Run(async () =>
                {
                    try
                    {
                        if (recipient.ClientSocket == null || !recipient.ClientSocket.Connected)
                        {
                            ServerLogger.LogLocalized("RosterSendSkippedNotConnected", ServerLogLevel.Debug, recipient.Username);
                            return;
                        }
                        /// <summary>
                        /// Sends the framed payload to the recipient, awaiting completion 
                        /// so the per-connection semaphore enforces ordered, non-interleaved writes
                        /// and any send errors or cancellation are observed.
                        /// </summary>
                        await SendFramedAsync(recipient, payload, cancellationToken).ConfigureAwait(false);
                        ServerLogger.LogLocalized("RosterSendSuccess", ServerLogLevel.Debug, recipient.Username);
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("RosterSendFailed", ServerLogLevel.Error, recipient.Username, ex.Message);
                    }
                }, cancellationToken);

                sendTasks.Add(task);
            }

            /// <summary> Awaits all sends. Use WhenAll so one failure doesn't cancel others. </summary>
            try
            {
                await Task.WhenAll(sendTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        /// <summary>
        /// Distributes a user's public key to all connected clients using a unified,
        /// protocol‑consistent PublicKeyResponse format:
        /// [opcode=PublicKeyResponse][originUid][lenKey][keyBytes][requesterUid]
        /// </summary>
        /// <param name="originUid">
        /// The UID of the user whose public key is being broadcast.
        /// </param>
        /// <param name="publicKey">
        /// The DER‑encoded RSA public key bytes to distribute.
        /// </param>
        /// <param name="cancellationToken">
        /// Cancellation token for the broadcast operation.
        /// </param>
        public static async Task BroadcastNewPublicKeyAsync(Guid originUid, byte[] publicKey, CancellationToken cancellationToken)
        {
            var snapshotUsers = Users.ToList();
            var sendTasks = new List<Task>(snapshotUsers.Count);

            foreach (var target in snapshotUsers)
            {
                if (!target.ClientSocket.Connected)
                {
                    continue;
                }

                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)PacketOpCode.PublicKeyResponse);
                builder.WriteUid(originUid);
                builder.WriteBytesWithLength(publicKey);
                builder.WriteUid(target.UID);

                byte[] payload = builder.GetPacketBytes();

                var sendTask = Task.Run(async () =>
                {
                    try
                    {
                        await SendFramedAsync(target, payload, cancellationToken).ConfigureAwait(false);
                        ServerLogger.LogLocalized("PublicKeyRelaySuccess", ServerLogLevel.Debug, target.Username);
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("PublicKeyRelayFailed", ServerLogLevel.Warn, target.Username, ex.Message);
                    }
                }, cancellationToken);

                sendTasks.Add(sendTask);
            }

            try 
            { 
                await Task.WhenAll(sendTasks).ConfigureAwait(false); 
            }
            catch (OperationCanceledException) 
            { }
        }

        /// <summary>
        /// Broadcasts a plain-text chat message from one client to all connected clients.
        /// Packet structure:
        ///   [4-byte big-endian length]
        ///   [1-byte opcode: PlainMessage]
        ///   [16-byte sender UID]
        ///   [16-byte recipient UID]
        ///   [4-byte message length][UTF-8 message bytes]
        /// </summary>
        /// <param name="messageText">The message content to broadcast.</param>
        /// <param name="senderUid">Unique identifier of the message sender.</param>
        public static async Task BroadcastPlainMessage(string messageText, Guid senderUid, CancellationToken cancellationToken)
        {
            // Snapshots current users
            var snapshotUsers = Users.ToList();

            var sendTasks = new List<Task>(snapshotUsers.Count);

            foreach (var target in snapshotUsers)
            {
                if (!target.ClientSocket.Connected)
                    continue;

                /// <summary> Builds the packet </summary>
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)PacketOpCode.PlainMessage);
                builder.WriteUid(senderUid);     // sender’s UID
                builder.WriteUid(target.UID);    // recipient UID placeholder
                builder.WriteString(messageText);// length+UTF-8 bytes

                byte[] payload = builder.GetPacketBytes();

                ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

                /// <summary> Per-target task, keep logging </summary>
                var sendTask = Task.Run(async () =>
                {
                    try
                    {
                        /// <summary> Sends framed payload to socket </summary>
                        await SendFramedAsync(target, payload, cancellationToken).ConfigureAwait(false);
                        ServerLogger.LogLocalized("MessageRelaySuccess", ServerLogLevel.Debug, target.Username);
                    }
                    catch (OperationCanceledException)
                    {

                    }
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("MessageRelayFailed", ServerLogLevel.Warn, target.Username, ex.Message);
                    }
                }, cancellationToken);

                /// <summary> Tracks task for later await </summary>
                sendTasks.Add(sendTask);
            }

            /// <summary> Waits all sends </summary>
            try
            {
                await Task.WhenAll(sendTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {

            }
        }
        
        /// <summary>
        /// Writes the server banner and startup instructions to the console.
        /// </summary>
        static void DisplayBanner()
        {
            Console.WriteLine("╔═══════════════════════════════════╗");
            Console.WriteLine("║        WPF Chat Server 1.0        ║");
            Console.WriteLine("╚═══════════════════════════════════╝");
            Console.WriteLine(LocalizationManager.GetString("BannerLine1"));
            Console.WriteLine(LocalizationManager.GetString("BannerLine2"));
        }

        /// <summary>
        /// Prompts the user to enter a valid TCP port or fallback to default.
        /// </summary>
        /// <returns>Valid port number to use</returns>
        static int GetPortFromUser()
        {
            int defaultPort = 7123;
            int chosenPort = defaultPort;

            Console.WriteLine(LocalizationManager.GetString("PortPrompt"));
            string input = ReadLineWithTimeout(7000);

            if (!string.IsNullOrWhiteSpace(input))
            {
                // Validates port number
                if (int.TryParse(input, out int port) && port >= 1000 && port <= 65535)
                {
                    chosenPort = port;
                }
                else
                {
                    // Asks user if they want to use default port
                    Console.WriteLine("Invalid port, would you like to use default port (7123)? (y/n): ");

                    // Uses ReadLineWithTimeout and normalizes null to empty string to satisfy nullable analysis
                    string confirmRaw = ReadLineWithTimeout(7000);
                    string confirm = (confirmRaw ?? string.Empty).Trim().ToLowerInvariant();

                    if (confirm == "y")
                    {
                        chosenPort = defaultPort;
                    }
                    else
                    {
                        Console.WriteLine("Exiting...");
                        Environment.Exit(0);
                    }
                }
            }

            return chosenPort;
        }

        /// <summary>
        /// Reads a line from the console with a timeout.
        /// </summary>
        /// <param name="timeoutMs">Timeout in milliseconds</param>
        /// <returns>User input or empty string if timeout or input is null</returns>
        static string ReadLineWithTimeout(int timeoutMs)
        {
            var task = Task.Run(() => Console.ReadLine());
            if (task.Wait(timeoutMs))
            {
                // Console.ReadLine() may return null; normalizes to empty string to satisfy nullable analysis.
                return task.Result ?? string.Empty;
            }

            return string.Empty;
        }

        /// <summary>
        /// Relays an already encrypted payload from a sender to a recipient.
        /// • Validates recipient connection and session state.
        /// • Ensures ciphertext is non-empty.
        /// • Builds packet (opcode + sender UID + recipient UID + length-prefixed ciphertext).
        /// • Frames packet for wire transport and sends.
        /// </summary>
        public static async Task RelayEncryptedMessageToAUser(byte[] ciphertext, Guid senderUid,
            Guid recipientUid, CancellationToken cancellationToken)
        {
            var recipient = Users.FirstOrDefault(u => u.UID == recipientUid);

            /// <summary>
            /// Checks that recipient exists and that socket is connected
            /// </summary>
            if (recipient?.ClientSocket == null || recipient.ClientSocket.Connected != true)
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn,
                    recipientUid.ToString(), "Recipient not connected");
                return;
            }

            /// <summary>
            /// Ensure recipient session is established before relaying
            /// </summary>
            if (!recipient.IsEstablished)
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn,
                    recipientUid.ToString(), "Recipient not established");
                return;
            }

            /// <summary>
            /// Validates ciphertext presence
            /// </summary>
            if (ciphertext == null || ciphertext.Length == 0)
            {
                ServerLogger.LogLocalized("ErrorEmptyCiphertext", ServerLogLevel.Warn,
                    senderUid.ToString(), recipientUid.ToString());
                return;
            }

            /// <summary>
            /// Builds encrypted-message packet: 
            /// opcode + sender UID + recipient UID + ciphertext
            /// </summary>
            var encMsgPacket = new PacketBuilder();
            encMsgPacket.WriteOpCode((byte)PacketOpCode.EncryptedMessage);
            encMsgPacket.WriteUid(senderUid);
            encMsgPacket.WriteUid(recipientUid);
            encMsgPacket.WriteBytesWithLength(ciphertext);

            var payloadInBytes = encMsgPacket.GetPacketBytes();

            try
            {
                /// <summary> Sends framed message packet </summary>
                await SendFramedAsync(recipient, payloadInBytes, cancellationToken).ConfigureAwait(false);
                ServerLogger.LogLocalized("EncryptedMessageRelaySuccess", ServerLogLevel.Debug, recipient.Username);
            }
            catch (OperationCanceledException)
            {
                // Cancelled gracefully
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn,
                    recipient.Username, ex.Message);
            }
        }


        /// <summary>
        /// Relays a public key request from one client to another specific client.
        /// Constructs a framed packet containing:
        ///   • opcode (PublicKeyRequest)
        ///   • requester UID
        ///   • target UID
        /// Sends it via SendFramedAsync. 
        /// If target is not connected/established, logs and returns non-fatally.
        /// </summary>
        public static async Task RelayPublicKeyRequest(Guid requesterUid, Guid targetUid, CancellationToken cancellationToken)
        {
            /// <summary> Takes a snapshot of connected users and locates the target by UID. </summary>
            var snapshotUsers = Users.ToList();
            var target = snapshotUsers.FirstOrDefault(u => u.UID == targetUid);

            /// <summary> Aborts if target socket is not connected. </summary>
            if (target?.ClientSocket?.Connected != true)
                return;

            /// <summary> Aborts if target user session is not yet established. </summary>
            if (!target.IsEstablished)
            {
                ServerLogger.LogLocalized("PublicKeyRequestRelayFailed",
                    ServerLogLevel.Warn, target?.Username ?? targetUid.ToString(), "Target not established");
                return;
            }

            /// <summary> Builds the packet with opcode, requester UID, and target UID. </summary>
            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)PacketOpCode.PublicKeyRequest);

            /// <summary> First the UID of the target (the one who owns the key) </summary>
            builder.WriteUid(targetUid);

            /// <summary> Then the UID of the requester (the one who requests the key) </summary>
            builder.WriteUid(requesterUid);

            /// <summary> Serializes packet to bytes and logs debug prefix. </summary>
            byte[] payload = builder.GetPacketBytes();
            ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

            try
            {
                /// <summary> Sends the framed packet to the target client. </summary>
                await SendFramedAsync(target, payload, cancellationToken).ConfigureAwait(false);
                ServerLogger.LogLocalized("PublicKeyRequestRelaySuccess", ServerLogLevel.Debug, target.Username);
            }
            catch (OperationCanceledException)
            {

            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("PublicKeyRequestRelayFailed", ServerLogLevel.Warn, target.Username, ex.Message);
            }
        }

        /// <summary>
        /// Relays a public key response to the requester only.
        /// </summary>
        public static async Task RelayPublicKeyToUser(Guid originUid, byte[] publicKey, Guid requesterUid,
            CancellationToken cancellationToken)
        {
            /// <summary> Snapshots user list to avoid collection-modification issues. </summary>
            var snapshotUsers = Users.ToList();
            var target = snapshotUsers.FirstOrDefault(usr => usr.UID == requesterUid);

            /// <summary> Validates requester connection. </summary>
            if (target == null || target.ClientSocket?.Connected != true)
            {
                ServerLogger.LogLocalized("PublicKeyResponseRelayFailed", ServerLogLevel.Warn,
                    requesterUid.ToString(), "Requester not connected");
                return;
            }

            /// <summary> Ensures requester session is established. </summary>
            if (!target.IsEstablished)
            {
                ServerLogger.LogLocalized("PublicKeyResponseRelayFailed",
                    ServerLogLevel.Warn, target.Username, "Requester not established");
                return;
            }

            /// <summary> Builds packet with origin UID, key, and requester UID. </summary>
            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)PacketOpCode.PublicKeyResponse);
            builder.WriteUid(originUid);
            builder.WriteBytesWithLength(publicKey ?? Array.Empty<byte>()); 
            builder.WriteUid(requesterUid);

            /// <summary> Serializes packet to byte array. </summary>
            byte[] payload = builder.GetPacketBytes();
            ServerLogger.Log(
                $"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}",
                ServerLogLevel.Debug);

            try
            {
                /// <summary> Sends packet asynchronously to requester. </summary>
                await SendFramedAsync(target, payload, cancellationToken).ConfigureAwait(false);
                ServerLogger.LogLocalized("PublicKeyResponseRelaySuccess", ServerLogLevel.Debug, target.Username);
            }
            catch (OperationCanceledException)
            {
                /// <summary> Expected cancellation during shutdown. </summary>
            }
            catch (Exception ex)
            {
                /// <summary> Logs any unexpected send failure. </summary>
                ServerLogger.LogLocalized("PublicKeyResponseRelayFailed", ServerLogLevel.Warn, target.Username, ex.Message);
            }
        }

        /// <summary>
        /// Sends a length-prefixed framed payload to a single recipient.
        /// Ensures the 4-byte length header is written in network byte order (big-endian)
        /// and serializes all writes to the recipient's NetworkStream using a per-UID SemaphoreSlim.
        /// Diagnostic logs show the outgoing header and a short payload prefix (temporary).
        /// </summary>
        public static async Task SendFramedAsync(ServerConnectionHandler recipient, byte[] payload, CancellationToken cancellationToken = default)
        {
            if (recipient == null)
            {
                throw new ArgumentNullException(nameof(recipient));
            }

            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            /// <summary> Ensures a SemaphoreSlim exists for this recipient, creating it only once in a thread-safe way. </summary> 
            var sem = _sendSemaphores.GetOrAdd(recipient.UID, _ => new SemaphoreSlim(1, 1));

            /// <summary>Waits to enter the semaphore for this recipient, ensuring only one send at a time per user. </summary>
            await sem.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                var tcpSocket = recipient.ClientSocket;
                var networkStream = tcpSocket?.GetStream();

                if (networkStream == null || tcpSocket?.Connected != true)
                {
                    throw new IOException("Recipient NetworkStream is unavailable or socket not connected.");
                }

                /// <summary>
                /// Builds the 4-byte length prefix explicitly in big-endian (network order).
                /// This avoids BitConverter endianness issues and guarantees consistent framing.
                /// </summary>
                int payloadLength = payload.Length;
                byte[] headerByte = new byte[4];
                headerByte[0] = (byte)(payloadLength >> 24);
                headerByte[1] = (byte)(payloadLength >> 16);
                headerByte[2] = (byte)(payloadLength >> 8);
                headerByte[3] = (byte)payloadLength;

                ServerLogger.Log($"OUTGOING_FRAME_HEADER={BitConverter.ToString(headerByte)} LEN={payload.Length}", ServerLogLevel.Debug);
                ServerLogger.Log($"BUILT_PAYLOAD_LEN={payload.Length}", ServerLogLevel.Debug);

                /// <summary> Logs prefix of payload for quick visual checksum (first 16 bytes or full if smaller) </summary>
                int prefixLength = Math.Min(16, payload.Length);

                /// <summary> If a prefix length is defined, copy that slice of the payload and log it in hex for debugging. </summary>
                if (prefixLength > 0)
                {
                    var prefixBytes = new byte[prefixLength];
                    Array.Copy(payload, 0, prefixBytes, 0, prefixLength);
                    ServerLogger.Log($"OUTGOING_FRAME_PAYLOAD_PREFIX={BitConverter.ToString(prefixBytes)}", ServerLogLevel.Debug);
                }

                try
                {
                    /// <summary>Write header first, then payload to the network stream (async). </summary>
                    await networkStream.WriteAsync(headerByte, 0, headerByte.Length, cancellationToken).ConfigureAwait(false);

                    /// <summary> If payload exists, write it after the header.</summary>
                    if (payload.Length > 0)
                    {
                        await networkStream.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                    }

                    /// <summary> Flush stream to ensure all bytes are sent immediately. </summary>
                    await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (IOException ioEx)
                {
                    ServerLogger.LogLocalized("SendFramedIoError", ServerLogLevel.Warn, recipient.Username ?? recipient.UID.ToString(), ioEx.Message);
                    throw;
                }
            }
            finally
            {
                /// <summary> Release semaphore so other send operations can proceed. </summary>
                sem.Release();
            }
        }

        /// <summary>
        /// Gracefully shuts down the server:
        /// • Stops listener and cancels accept loop
        /// • Broadcasts ForceDisconnect to all clients
        /// • Closes sockets and clears Users
        /// • Resets accept CTS for restart
        /// </summary>
        public static async Task ShutdownAsync(CancellationToken cancellationToken)
        {
            Console.WriteLine(LocalizationManager.GetString("ServerShutdown"));

            // Stops listener and cancels accept loop
            Listener?.Stop();
            _acceptCts?.Cancel();

            // Broadcasts a force disconnect packet
            try
            {
                await BroadcastForceDisconnect(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) 
            { 
            
            }

            catch (Exception ex)
            {
                ServerLogger.LogLocalized("BroadcastForceDisconnectFailed", ServerLogLevel.Warn, ex.Message);
            }

            // Briefs delay to flush packets
            await Task.Delay(100, cancellationToken).ContinueWith(_ => { });

            // Closes sockets and clears roster
            lock (Users)
            {
                foreach (var usr in Users.ToList())
                    usr.ClientSocket?.Dispose();
                Users.Clear();
            }

            // Resets accept CTS
            _acceptCts?.Dispose();
            _acceptCts = new CancellationTokenSource();

            Console.WriteLine(LocalizationManager.GetString("ServerShutdownComplete"));
        }
    }
}
