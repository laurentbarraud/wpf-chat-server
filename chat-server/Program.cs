/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 4th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

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
            // <summary> Initializes localization based on system language </summary>
            string uiLang = CultureInfo.CurrentCulture.TwoLetterISOLanguageName.Equals("fr", StringComparison.OrdinalIgnoreCase) ? "fr" : "en";
            LocalizationManager.Initialize(uiLang);

            // <summary> Ensures console supports UTF-8 output </summary>
            Console.OutputEncoding = Encoding.UTF8;

            // <summary> Cancellation token for accept loop and background tasks </summary>
            _acceptCts = new CancellationTokenSource();
            CancellationToken token = _acceptCts.Token;

            // <summary> Graceful Ctrl+C shutdown </summary>
            Console.CancelKeyPress += (s, e) => 
            { 
                e.Cancel = true; _exitByCtrlC = true; 
                Listener?.Stop(); 
                _acceptCts.Cancel(); 
            };

            // <summary> Graceful shutdown on process exit </summary>
            AppDomain.CurrentDomain.ProcessExit += (s, e) => 
            { 
                if (!_exitByCtrlC) 
                { 
                    Listener?.Stop(); _acceptCts.Cancel(); 
                } 
            };

            // <summary> Display banner and prompt for port </summary>
            DisplayBanner();
            int port = GetPortFromUser();

            try
            {
                Users = new List<ServerConnectionHandler>();
                Listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
                Listener.Start();
                Console.WriteLine(string.Format(LocalizationManager.GetString("ServerStartedOnPort"), port));

                // <summary> Accept loop — exits when Listener.Stop() is called or token is cancelled </summary>
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

                    // <summary> Handles accepted client on background task </summary>
                    _ = Task.Run(async () =>
                    {
                        ServerConnectionHandler? client = null;
                        try
                        {
                            var networkStream = tcpClient.GetStream();

                            // <summary> Read 4-byte big-endian header </summary>
                            byte[] header = await PacketReader.ReadExactAsync(networkStream, 4, token).ConfigureAwait(false);
                            int payloadLength = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
                            if (payloadLength <= 0 || payloadLength > 65_536) { tcpClient.Close(); return; }

                            // <summary> Reads payload and parse handshake </summary>
                            byte[] payload = await PacketReader.ReadExactAsync(networkStream, payloadLength, token).ConfigureAwait(false);
                            using var memoryStream = new MemoryStream(payload);
                            var reader = new PacketReader(memoryStream);

                            if ((ServerPacketOpCode)await reader.ReadByteAsync(token).ConfigureAwait(false) != ServerPacketOpCode.Handshake)
                            { 
                                tcpClient.Close(); return; 
                            }

                            string username = await reader.ReadStringAsync(token).ConfigureAwait(false);
                            Guid uid = await reader.ReadUidAsync(token).ConfigureAwait(false);

                            // <summary> Reads and validates the public key from the handshake payload (always present in protocol) </summary>
                            int publicKeyLength = await reader.ReadInt32NetworkOrderAsync(token).ConfigureAwait(false);
                            const int MaxPublicKeyLength = 65_536;
                            if (publicKeyLength < 0 || publicKeyLength > MaxPublicKeyLength) { tcpClient.Close(); return; }

                            byte[] publicKeyDer = await PacketReader.ReadExactAsync(memoryStream, publicKeyLength, token).ConfigureAwait(false);

                            // <summary> Initializes client after handshake with the raw public key (can be empty) </summary>
                            client = new ServerConnectionHandler(tcpClient);
                            client.InitializeAfterHandshake(username, uid, publicKeyDer, token);

                            // <summary> Adds client to roster and log localized connection </summary>
                            lock (Users) { Users.Add(client); }
                            ServerLogger.LogLocalized("ClientConnected", ServerLogLevel.Info);

                            // <summary> Sends HandshakeAck (framed) </summary>
                            var ack = new PacketBuilder();
                            ack.WriteOpCode((byte)ServerPacketOpCode.HandshakeAck);
                            await SendFramedAsync(client, ack.GetPacketBytes(), token).ConfigureAwait(false);

                            // <summary> Broadcasts roster after ack so all clients get updated keys (empty keys included) </summary>
                            await BroadcastRosterAsync(token).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) 
                        { 
                            tcpClient.Close(); 
                        }
                        catch
                        {
                            tcpClient.Close();
                            if (client != null)
                            {
                                lock (Users)
                                {
                                    Users.Remove(client);
                                }
                            }
                        }
                    }, token);
                }

                // <summary> Graceful shutdown once loop exits </summary>
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

            // Snapshots current users
            var snapshot = Users.ToList();

            /// <summary>
            /// FirstOrDefault returns a nullable Client if no match is found,
            /// so we declare goneUser as Client? to reflect that.
            /// </summary>
            ServerConnectionHandler? goneUser = snapshot.FirstOrDefault(u => u.UID == disconnectedGuid);

            /// <summary>
            /// Safely guards the removal logic
            /// </summary>
            if (goneUser is not null)
            {
                lock (Users)
                    Users.Remove(goneUser);
            }

            // Chooses a safe username fallback:
            // uses disconnected GUID string when username is unavailable
            string username = goneUser?.Username ?? disconnectedUserId.ToString();

            /// <summary>
            /// Builds the framed DisconnectNotify for each remaining client
            /// and sends it if their socket is connected.
            /// </summary>
            var sendTasks = new List<Task>();

            foreach (var listener in snapshot)
            {
                if (!listener.ClientSocket.Connected)
                    continue;

                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.DisconnectNotify);
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
                builder.WriteOpCode((byte)ServerPacketOpCode.ForceDisconnectClient);
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
            // Snapshots current users
            var snapshot = Users.ToList();

            // Builds the roster payload
            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)ServerPacketOpCode.RosterBroadcast);

            // Writes roster count as 4-byte big-endian Int32
            builder.WriteInt32NetworkOrder(snapshot.Count);

            foreach (var target in snapshot)
            {
                builder.WriteUid(target.UID);
                builder.WriteString(target.Username);
                byte[] pk = target.PublicKeyDer ?? Array.Empty<byte>();
                builder.WriteBytesWithLength(pk);
            }

            byte[] payload = builder.GetPacketBytes();

            // Shows what the builder returned before sending
            ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

            // Launches send tasks for all recipients
            var sendTasks = new List<Task>(snapshot.Count);
            foreach (var recipient in snapshot)
            {
                var task = Task.Run(async () =>
                {
                    try
                    {
                        // If recipient socket disconnected
                        if (recipient.ClientSocket == null || !recipient.ClientSocket.Connected)
                        {
                            ServerLogger.LogLocalized("RosterSendSkippedNotConnected", ServerLogLevel.Debug, recipient.Username);
                            return;
                        }

                        // Sends the framed payload to the recipient, awaiting completion so the
                        // per-connection semaphore enforces ordered, non-interleaved writes and
                        // any send errors or cancellation are observed.
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

            // Awaits all sends. Use WhenAll so one failure doesn't cancel others.
            try
            {
                await Task.WhenAll(sendTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
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
            var snapshot = Users.ToList();

            var sendTasks = new List<Task>(snapshot.Count);

            foreach (var target in snapshot)
            {
                if (!target.ClientSocket.Connected)
                    continue;

                // Builds the packet
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.PlainMessage);
                builder.WriteUid(senderUid);     // sender’s UID
                builder.WriteUid(target.UID);    // recipient UID placeholder
                builder.WriteString(messageText);// length+UTF-8 bytes

                byte[] payload = builder.GetPacketBytes();

                // Shows what the builder returned before sending
                ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

                // Per-target task that preserves existing logging
                var sendTask = Task.Run(async () =>
                {
                    try
                    {
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

                sendTasks.Add(sendTask);
            }

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
        /// Relays an encrypted payload from sender to recipient.
        /// • Validates recipient connection and ciphertext presence.
        /// • Builds packet: opcode, sender UID, recipient UID, length-prefixed ciphertext.
        /// • Frames packet for wire transport (4-byte length prefix + payload).
        /// • Sends framed packet via SendFramedAsync and logs success or failure.
        /// </summary>
        public static async Task RelayEncryptedMessageToAUser(byte[] ciphertext, Guid senderUid, Guid recipientUid, CancellationToken cancellationToken)
        {
            // Snapshots current users to avoid collection modification issues.
            var recipient = Users.FirstOrDefault(u => u.UID == recipientUid);

            // Ensures recipient exists and is connected.
            if (recipient?.ClientSocket == null || recipient.ClientSocket.Connected != true)
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn, recipientUid.ToString(), "Recipient not connected");
                return;
            }

            // Ensures recipient session is established before relaying encrypted payload
            if (!(recipient.IsEstablished))
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn, recipientUid.ToString(), "Recipient not established");
                return;
            }

            // Validates ciphertext presence.
            if (ciphertext == null || ciphertext.Length == 0)
            {
                ServerLogger.LogLocalized("ErrorEmptyCiphertext", ServerLogLevel.Warn, senderUid.ToString(), recipientUid.ToString());
                return;
            }

            // Builds encrypted-message packet: opcode + sender UID + recipient UID + length-prefixed ciphertext.
            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)ServerPacketOpCode.EncryptedMessage);
            builder.WriteUid(senderUid);
            builder.WriteUid(recipientUid);
            builder.WriteBytesWithLength(ciphertext);

            byte[] payload = builder.GetPacketBytes();

            try
            {
                // Sends framed packet to recipient.
                await SendFramedAsync(recipient, payload, cancellationToken).ConfigureAwait(false);
                ServerLogger.LogLocalized("EncryptedMessageRelaySuccess", ServerLogLevel.Debug, recipient.Username);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn, recipient.Username, ex.Message);
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
            var snapshot = Users.ToList();
            var target = snapshot.FirstOrDefault(u => u.UID == targetUid);

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
            builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyRequest);

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
        public static async Task RelayPublicKeyToUser(Guid originUid, byte[] publicKeyDer, Guid requesterUid,
            CancellationToken cancellationToken)
        {
            /// <summary> Snapshots user list to avoid collection-modification issues. </summary>
            var snapshot = Users.ToList();
            var target = snapshot.FirstOrDefault(usr => usr.UID == requesterUid);

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
            builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
            builder.WriteUid(originUid);
            builder.WriteBytesWithLength(publicKeyDer ?? Array.Empty<byte>()); 
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

            // Ensures a SemaphoreSlim exists for this recipient, creating it only once in a thread-safe way.
            var sem = _sendSemaphores.GetOrAdd(recipient.UID, _ => new SemaphoreSlim(1, 1));

            await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
            
            try
            {
                var tcp = recipient.ClientSocket;
                var stream = tcp?.GetStream();
                if (stream == null || tcp?.Connected != true)
                    throw new IOException("Recipient NetworkStream is unavailable or socket not connected.");

                // Builds the 4-byte length prefix explicitly in big-endian (network order).
                // This avoids BitConverter endianness issues and guarantees consistent framing.
                int length = payload.Length;
                byte[] header = new byte[4];
                header[0] = (byte)(length >> 24);
                header[1] = (byte)(length >> 16);
                header[2] = (byte)(length >> 8);
                header[3] = (byte)length;

                // Temporary diagnostic logs
                ServerLogger.Log($"OUTGOING_FRAME_HEADER={BitConverter.ToString(header)} LEN={payload.Length}", ServerLogLevel.Debug);
                ServerLogger.Log($"BUILT_PAYLOAD_LEN={payload.Length}", ServerLogLevel.Debug);

                // Logs prefix of payload for quick visual checksum (first 16 bytes or full if smaller)
                int prefixLen = Math.Min(16, payload.Length);
                if (prefixLen > 0)
                {
                    var prefix = new byte[prefixLen];
                    Array.Copy(payload, 0, prefix, 0, prefixLen);
                    ServerLogger.Log($"OUTGOING_FRAME_PAYLOAD_PREFIX={BitConverter.ToString(prefix)}", ServerLogLevel.Debug);
                }

                try
                {
                    // Writes header then payload in order, using async APIs
                    await stream.WriteAsync(header, 0, header.Length, cancellationToken).ConfigureAwait(false);
                    if (payload.Length > 0)
                    {
                        await stream.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                    }

                    await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (IOException ioEx)
                {
                    ServerLogger.LogLocalized("SendFramedIoError", ServerLogLevel.Warn, recipient.Username ?? recipient.UID.ToString(), ioEx.Message);
                    throw;
                }
            }
            finally
            {
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
