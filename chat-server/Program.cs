/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 18th, 2025</date>

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
        /// • Initializes localization and console encoding.  
        /// • Wires Ctrl+C and ProcessExit to call Shutdown.  
        /// • Starts a TcpListener and accepts incoming clients with AcceptTcpClientAsync.  
        /// • Adds only fully-initialized ServerConnectionHandler instances to Users list.  
        /// • Sends an explicit HandshakeAck to the client before broadcasting roster.  
        /// • Uses locks around Users for thread-safety and cancels background work on shutdown.
        /// </summary>
        public static void Main(string[] args)
        {
            // Initializes localization based on OS culture
            string twoLetterLanguageCode = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            string uiLang = twoLetterLanguageCode.Equals("fr", StringComparison.OrdinalIgnoreCase) ? "fr" : "en";
            LocalizationManager.Initialize(uiLang);

            // Configures console for UTF-8 output
            Console.OutputEncoding = Encoding.UTF8;

            CancellationToken token = _acceptCts.Token;

            // Graceful shutdown then exits
            Console.CancelKeyPress += async (sender, e) =>
            {
                e.Cancel = true;
                _exitByCtrlC = true;
                try
                {
                    await ShutdownAsync(_acceptCts.Token).ConfigureAwait(false);
                }
                catch
                {
                }
                Environment.Exit(0);
            };

            // Normal shutdown (skip if Ctrl+C already requested)
            AppDomain.CurrentDomain.ProcessExit += async (sender, e) =>
            {
                if (_exitByCtrlC)
                    return;

                try
                {
                    await ShutdownAsync(_acceptCts.Token).ConfigureAwait(false);
                }
                catch
                {
                }
            };

            // Displays banner and prompts user for port
            DisplayBanner();
            int port = GetPortFromUser();

            try
            {
                Users = new List<ServerConnectionHandler>();
                Listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
                Listener.Start();

                Console.WriteLine(string.Format(LocalizationManager.GetString("ServerStartedOnPort"), port));

                // Async accept loop — runs until _acceptCts is cancelled or Listener is stopped
                var acceptTask = Task.Run(async () =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        TcpClient acceptedTcpClient;
                        
                        try
                        {
                            acceptedTcpClient = await Listener.AcceptTcpClientAsync().ConfigureAwait(false);
                        }
                        catch (ObjectDisposedException)
                        {
                            // Listener stopped; exits loop cleanly
                            break;
                        }
                        catch (Exception ex)
                        {
                            ServerLogger.LogLocalized("AcceptTcpClientFailed", ServerLogLevel.Warn, ex.Message);

                            try
                            {
                                // backs off briefly; cancellation will interrupt this delay
                                await Task.Delay(100, token).ConfigureAwait(false);
                            }
                            catch
                            {
                            }

                            continue;
                        }

                        // Process the accepted socket on a background task so the accept loop remains responsive
                        _ = Task.Run(async () =>
                        {
                            ServerConnectionHandler? client = null;
                            try
                            {
                                // Uses a local alias for clarity
                                var ns = acceptedTcpClient.GetStream();

                                // Reads 4-byte big-endian handshake length header
                                byte[] headerBytes = await PacketReader.ReadExactAsync(ns, 4, token).ConfigureAwait(false);
                                ServerLogger.Log($"READ_HEADER={BitConverter.ToString(headerBytes)}", ServerLogLevel.Debug);

                                // Interprets the 4-byte header explicitly as big-endian
                                int payloadLength =
                                    (headerBytes[0] << 24) |
                                    (headerBytes[1] << 16) |
                                    (headerBytes[2] << 8) |
                                    headerBytes[3];

                                const int MaxHandshakePayload = 65_536;
                                if (payloadLength <= 0 || payloadLength > MaxHandshakePayload)
                                {
                                    ServerLogger.LogLocalized("ErrorInvalidHandshakeLength", ServerLogLevel.Warn, "?", payloadLength.ToString());
                                    try 
                                    { 
                                        acceptedTcpClient.Close(); 
                                    } 
                                    catch { }
                                    
                                    return;
                                }

                                // Reads handshake payload into memory
                                byte[] payload = await PacketReader.ReadExactAsync(ns, payloadLength, token).ConfigureAwait(false);

                                // Parses handshake from in-memory buffer (safe, synchronous parsing off the network)
                                using var memoryStream = new MemoryStream(payload);
                                var handshakeReader = new PacketReader(memoryStream);

                                var opcode = (ServerPacketOpCode)await handshakeReader.ReadByteAsync(token).ConfigureAwait(false);
                                if (opcode != ServerPacketOpCode.Handshake)
                                {
                                    ServerLogger.LogLocalized("ErrorInvalidOperationException", ServerLogLevel.Warn, "?", $"{(byte)opcode}");
                                    try { acceptedTcpClient.Close(); } catch { }
                                    return;
                                }

                                string username = await handshakeReader.ReadStringAsync(token).ConfigureAwait(false);
                                Guid uid = await handshakeReader.ReadUidAsync(token).ConfigureAwait(false);
                                int publicKeyLength = await handshakeReader.ReadInt32NetworkOrderAsync(token).ConfigureAwait(false);

                                const int MaxPublicKeyLength = 65_536;
                                if (publicKeyLength <= 0 || publicKeyLength > MaxPublicKeyLength)
                                {
                                    ServerLogger.LogLocalized("ErrorPublicKeyLengthInvalid", ServerLogLevel.Warn, uid.ToString());
                                    try { acceptedTcpClient.Close(); } catch { }
                                    return;
                                }

                                // In-memory read of public key bytes 
                                byte[] publicKeyDer = await PacketReader.ReadExactAsync(memoryStream, publicKeyLength, token).ConfigureAwait(false);

                                // Handshake validated: creates handler and initializes it (starts cancellable reader)
                                client = new ServerConnectionHandler(acceptedTcpClient);
                                client.InitializeAfterHandshake(username, uid, publicKeyDer, token);

                                // Adds to Users only after successful handshake and reader started
                                lock (Users)
                                {
                                    Users.Add(client);
                                }

                                // Builds HandshakeAck
                                var ackBuilder = new PacketBuilder();
                                ackBuilder.WriteOpCode((byte)ServerPacketOpCode.HandshakeAck);
                                byte[] ackPayload = ackBuilder.GetPacketBytes();

                                ServerLogger.Log($"BUILDER_RETURNS_LEN={ackPayload.Length} PREFIX={BitConverter.ToString(ackPayload.Take(Math.Min(24, ackPayload.Length)).ToArray())}", ServerLogLevel.Debug);

                                // Uses the centralized framed send helper to guarantee atomic, serialized sends
                                await SendFramedAsync(client, ackPayload, token).ConfigureAwait(false);

                                ServerLogger.LogLocalized("SentHandshakeAck", ServerLogLevel.Debug, client.Username);

                                // Ensures roster broadcast happens after the ack is flushed
                                try
                                {
                                    await BroadcastRosterAsync(token).ConfigureAwait(false);
                                }
                                catch (OperationCanceledException) 
                                { }
                                catch (Exception ex)
                                {
                                    ServerLogger.LogLocalized("BroadcastRosterFailed", ServerLogLevel.Warn, ex.Message);
                                }
                            }
                            catch (OperationCanceledException)
                            {
                                try 
                                { 
                                    acceptedTcpClient.Close(); 
                                } 
                                catch { }
                            }
                            catch (Exception ex)
                            {
                                ServerLogger.LogLocalized("AcceptHandshakeFailed", ServerLogLevel.Warn, ex.Message);
                                try { acceptedTcpClient.Close(); } catch { }

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
                }, token);

                // Blocks main until accept loop completes
                acceptTask.GetAwaiter().GetResult();

            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nFailed to start server on port {port}: {ex.Message}");
                Console.WriteLine("Exiting...");
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
        /// Constructs a framed packet (4-byte length prefix + payload) containing:
        ///   • opcode (PublicKeyRequest)
        ///   • requester UID
        ///   • target UID
        /// Then sends it via SendFramedAsync and logs success or failure.
        /// </summary>
        /// <param name="requesterUid">Unique identifier of the requesting client.</param>
        /// <param name="targetUid">Unique identifier of the client whose key is requested.</param>
        public static async Task RelayPublicKeyRequest(Guid requesterUid, Guid targetUid, CancellationToken cancellationToken)
        {
            // Snapshots current users
            var snapshot = Users.ToList();

            var target = snapshot.FirstOrDefault(u => u.UID == targetUid);
            if (target?.ClientSocket?.Connected != true)
                return;

            // Ensures target session is established before forwarding a key request
            if (!(target.IsEstablished))
            {
                ServerLogger.LogLocalized("PublicKeyRequestRelayFailed",
                    ServerLogLevel.Warn, target?.Username ?? targetUid.ToString(), "Target not established");
                return;
            }

            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyRequest);
            builder.WriteUid(requesterUid);
            builder.WriteUid(targetUid);

            // Frames payload for on-the-wire transport
            byte[] payload = builder.GetPacketBytes();

            // Shows what the builder returned before sending
            ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

            try
            {
                await SendFramedAsync(target, payload, cancellationToken).ConfigureAwait(false);
                ServerLogger.LogLocalized("PublicKeyRequestRelaySuccess",
                    ServerLogLevel.Debug, target.Username);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("PublicKeyRequestRelayFailed",
                    ServerLogLevel.Warn, target.Username, ex.Message);
            }
        }

        /// <summary>
        /// Sends a PublicKeyResponse packet back to the original requester.
        /// Packet structure:
        ///   [4-byte length prefix]
        ///   [1-byte opcode: PublicKeyResponse]
        ///   [16-byte origin UID]
        ///   [4-byte byte-array length][DER-encoded RSA public key bytes]
        ///   [16-byte requester UID]
        /// </summary>
        /// <param name="originUid">UID of the client providing its public key.</param>
        /// <param name="publicKeyDer">The RSA public key in DER-encoded byte array format.</param>
        /// <param name="requesterUid">UID of the client that requested the key.</param>
        public static async Task RelayPublicKeyToUser(Guid originUid, byte[] publicKeyDer, Guid requesterUid, CancellationToken cancellationToken)
        {
            // Snapshots current users
            var snapshot = Users.ToList();

            var target = snapshot.FirstOrDefault(usr => usr.UID == requesterUid);
            if (target?.ClientSocket?.Connected != true)
                return;

            // Ensures requester session is established before relaying a key response
            if (!(target.IsEstablished))
            {
                ServerLogger.LogLocalized("PublicKeyResponseRelayFailed",
                    ServerLogLevel.Warn, target?.Username ?? requesterUid.ToString(), "Requester not established");
                return;
            }

            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
            builder.WriteUid(originUid);
            builder.WriteBytesWithLength(publicKeyDer);
            builder.WriteUid(requesterUid);

            // Frames payload for on-the-wire transport
            byte[] payload = builder.GetPacketBytes();

            // Shows what the builder returned before sending
            ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

            try
            {
                await SendFramedAsync(target, payload, cancellationToken).ConfigureAwait(false);
                ServerLogger.LogLocalized("PublicKeyResponseRelaySuccess",
                    ServerLogLevel.Debug, target.Username);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("PublicKeyResponseRelayFailed",
                    ServerLogLevel.Warn, target.Username, ex.Message);
            }
        }

        // Removes and disposes the per-connection semaphore for the given UID if present.
        // Safe to call from other classes.
        internal static void RemoveAndDisposeSendSemaphore(Guid uid)
        {
            if (_sendSemaphores.TryRemove(uid, out var sem))
            {
                try
                {
                    sem?.Dispose();
                }
                catch
                {
                }
            }
        }

        /// <summary>
        /// Sends a length-prefixed framed payload to a single recipient.
        /// Ensures the 4-byte length header is written in network byte order (big-endian)
        /// and serializes all writes to the recipient's NetworkStream using a per-UID SemaphoreSlim.
        /// Diagnostic logs show the outgoing header and a short payload prefix (temporary).
        /// </summary>
        private static async Task SendFramedAsync(ServerConnectionHandler recipient, byte[] payload, CancellationToken cancellationToken = default)
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
