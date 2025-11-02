/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 2nd, 2025</date>

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
                                // Task.Delay is used to avoid a too fast loop in case of a temporary failure of
                                // AcceptTcpClientAsync (for example, if the listener is temporarily unavailable).
                                // The token allows to properly interrupt this delay if the server is shutting down.
                                await Task.Delay(100, token).ConfigureAwait(false); 
                            } 
                            catch 
                            { 
                            }
                            continue;
                        }

                        // Processes the accepted socket on a background task, so accept loop stays responsive
                        _ = Task.Run(async () =>
                        {
                            var client = TryCreateHandler(acceptedTcpClient);
                            if (client == null)
                            {
                                return;
                            }

                            lock (Users)
                            {
                                Users.Add(client);
                            }

                            // Builds and send explicit HandshakeAck to the new client before roster broadcast
                            try
                            {
                                var ackBuilder = new PacketBuilder();
                                ackBuilder.WriteOpCode((byte)ServerPacketOpCode.HandshakeAck);
                                byte[] ackPayload = ackBuilder.GetPacketBytes();

                                int ackLenNetwork = IPAddress.HostToNetworkOrder(ackPayload.Length);
                                byte[] ackHeader = BitConverter.GetBytes(ackLenNetwork);

                                NetworkStream stream = client.ClientSocket.GetStream();

                                // Uses async writes with the shared cancellation token
                                await stream.WriteAsync(ackHeader, 0, ackHeader.Length, token).ConfigureAwait(false);
                                await stream.FlushAsync(token).ConfigureAwait(false);
                                await stream.WriteAsync(ackPayload, 0, ackPayload.Length, token).ConfigureAwait(false);
                                await stream.FlushAsync(token).ConfigureAwait(false);

                                ServerLogger.LogLocalized("SentHandshakeAck", ServerLogLevel.Debug, client.Username);
                            }
                            catch (Exception ex)
                            {
                                // If ack send fails, close socket and remove client to avoid half-open connection
                                ServerLogger.LogLocalized("HandshakeAckSendFailed", ServerLogLevel.Warn, client.UID.ToString(), ex.Message);
                                try { client.ClientSocket?.Close(); } catch { }
                                lock (Users) { Users.Remove(client); }
                                return;
                            }

                            try
                            {
                                // Awaiting ensures ack is flushed before roster is sent and surfaces errors here
                                await BroadcastRosterAsync(token).ConfigureAwait(false);
                            }
                            catch (OperationCanceledException) 
                            { 
                            }
                            catch (Exception ex)
                            {
                                ServerLogger.LogLocalized("BroadcastRosterFailed", ServerLogLevel.Warn, ex.Message);
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
            builder.WriteString(snapshot.Count.ToString());

            foreach (var target in snapshot)
            {
                builder.WriteUid(target.UID);
                builder.WriteString(target.Username);
                byte[] pk = target.PublicKeyDer ?? Array.Empty<byte>();
                builder.WriteBytesWithLength(pk);
            }

            byte[] payload = builder.GetPacketBytes();

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
        /// Frames a raw payload with a 4‑byte big‑endian length prefix for network transmission.
        /// </summary>
        /// <param name="payload">Raw packet payload bytes (opcode + body).</param>
        /// <returns>
        /// A new byte array containing a 4‑byte network-order (big-endian) length prefix followed by the payload.
        /// This buffer is ready to be written directly to the socket stream.
        /// </returns>
        static byte[] Frame(byte[] payload)
        {
            using MemoryStream memoryStream = new MemoryStream();
            using BinaryWriter binaryWriter = new BinaryWriter(memoryStream);
            binaryWriter.Write(IPAddress.HostToNetworkOrder(payload.Length));
            binaryWriter.Write(payload);
            return memoryStream.ToArray();
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
        /// Relays an encrypted payload from sender to recipient:
        /// • Validates recipient connection and ciphertext presence.
        /// • Builds packet: opcode, sender UID, recipient UID, length-prefixed ciphertext.
        /// • Frames packet for wire transport (4-byte length prefix + payload).
        /// • Sends framed packet via SendFramedAsync and logs success or failure.
        /// </summary>
        public static async Task RelayEncryptedMessageToAUser(byte[] ciphertext, Guid senderUid, Guid recipientUid, CancellationToken cancellationToken)
        {
            // Snapshots current users
            var snapshot = Users.ToList();

            // Finds recipient and ensures socket is connected.
            var recipient = snapshot.FirstOrDefault(u => u.UID == recipientUid);
            if (recipient == null || recipient.ClientSocket == null || recipient.ClientSocket.Connected != true)
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn, recipientUid.ToString(), "Recipient not connected");
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

            // Frames payload for on-the-wire transport.
            byte[] payload = builder.GetPacketBytes();

            // Sends framed packet via SendFramedAsync and logs outcome.
            try
            {
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

            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyRequest);
            builder.WriteUid(requesterUid);
            builder.WriteUid(targetUid);

            byte[] payload = builder.GetPacketBytes();

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

            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
            builder.WriteUid(originUid);
            builder.WriteBytesWithLength(publicKeyDer);
            builder.WriteUid(requesterUid);

            byte[] payload = builder.GetPacketBytes();

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

            // Ensure a SemaphoreSlim exists for this recipient, creating it only once in a thread-safe way.
            // GetOrAdd returns an existing semaphore if present, or atomically inserts the provided factory result.
            // The semaphore is created with initial/count 1 so only one async writer can enter at a time.
            // This serializes async WriteAsync/FlushAsync calls to the same client's NetworkStream, preventing
            // interleaved bytes that would corrupt the length-prefixed framing.
            var sem = _sendSemaphores.GetOrAdd(recipient.UID, _ => new SemaphoreSlim(1, 1));

            await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var stream = recipient.ClientSocket.GetStream();

                // Builds network-order header
                int payloadLenNetwork = IPAddress.HostToNetworkOrder(payload.Length);
                byte[] header = BitConverter.GetBytes(payloadLenNetwork);

                // Writes header then payload in order, using async APIs
                await stream.WriteAsync(header, 0, header.Length, cancellationToken).ConfigureAwait(false);
                await stream.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                sem.Release();
            }
        }

        /// <summary>
        /// • Gracefully stops the listener and cancels background accept/dispatch work.
        /// • Broadcasts a framed ForceDisconnectClient packet to all clients.
        /// • Closes all client sockets and clears Users.
        /// </summary>
        public static async Task ShutdownAsync(CancellationToken cancellationToken)
        {
            Console.WriteLine(LocalizationManager.GetString("ServerShutdown"));

            // Stops accepting new clients
            try
            { 
                Listener?.Stop(); 
            } 
            catch 
            { 
            }

            // Cancels accept loop and any background tasks
            try 
            { 
                _acceptCts?.Cancel(); 
            } 
            catch 
            { 
            }

            // Broadcasts a ForceDisconnect to all clients (uses provided token)
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

            // Allow in-flight packets to traverse briefly (100 ms)
            try
            {
                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            // Closes all client sockets and clears the roster
            try
            {
                lock (Users)
                {
                    foreach (var usr in Users.ToList())
                    {
                        try { usr.ClientSocket?.Close(); } catch { }
                    }
                    Users.Clear();
                }
            }
            catch { }

            // Disposes and recreates the accept CancellationTokenSource for possible restart
            try
            {
                _acceptCts?.Dispose();
                _acceptCts = new CancellationTokenSource();
            }
            catch { }

            try { Console.WriteLine(LocalizationManager.GetString("ServerShutdownComplete")); } catch { }
        }

        /// <summary>
        /// Attempts to construct a ServerConnectionHandler from a raw TcpClient.
        /// On failure this method closes the raw socket and returns null
        /// </summary>
        private static ServerConnectionHandler? TryCreateHandler(TcpClient tcp)
        {
            try
            {
                // Constructor performs handshake synchronously and may throw on invalid data
                return new ServerConnectionHandler(tcp);
            }
            catch (Exception ex)
            {
                // Initialization failed: logs and ensures raw socket is closed
                ServerLogger.LogLocalized("ErrorInitializeClient", ServerLogLevel.Warn, ex.Message);
                try
                {
                    tcp?.Close();
                }
                catch
                {
                }
                return null;
            }
        }
    }
}
