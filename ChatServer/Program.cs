/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>July 15th, 2026</date>

using System;
using ChatServer.Helpers;
using ChatProtocol.Net.IO;
using ChatProtocol.Net;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ChatServer
{
    public class Program
    {
        // Internal properties

        // Holds the current connected client handlers
        internal static List<ServerConnectionHandler> Users = new List<ServerConnectionHandler>();

        // Private members

        // Cancellation token source used to stop the accept loop and shutdown accepting new clients
        private static CancellationTokenSource _acceptCts = new CancellationTokenSource();

        // Port currently used by the listener (needed to recreate it on startAccepting).
        private static int _currentPort;

        // True when the server shutdown was initiated by Ctrl+C
        private static bool _exitByCtrlC;

        // Maps each connected user's UID to a per-connection SemaphoreSlim
        // used to serialize async writes to that user's NetworkStream.
        // A semaphore is created for each user when they connect and removed when they disconnect.
        // This ensures only one async send runs at a time per client, preventing
        // interleaved writes that would corrupt length-prefixed framing.
        private static readonly ConcurrentDictionary<Guid, SemaphoreSlim> _sendSemaphores =
            new ConcurrentDictionary<Guid, SemaphoreSlim>();

        // Flag indicating whether we are currently accepting new clients.
        private static bool AcceptingClients = true;

        // TCP listener that accepts incoming client connections
        private static TcpListener? Listener;

        // Maximum number of clients allowed to connect simultaneously.
        // Only affects new connections; existing clients are not kicked when the limit is lowered.
        private static int MaxClients = 30;

        /// <summary>
        /// Entry point — server accept loop with handshake and command console.
        /// </summary>
        public static async Task Main(string[] args)
        {
            // Detects the OS UI language (two-letter ISO code).
            string osLanguage = CultureInfo.CurrentCulture.TwoLetterISOLanguageName.ToLowerInvariant();

            string appLanguage;

            switch (osLanguage)
            {
                case "fr":
                    appLanguage = "fr";
                    break;

                case "es":
                    appLanguage = "es";
                    break;

                default:
                    // Default language if nothing matches
                    appLanguage = "en";
                    break;
            }

            LocalizationManager.Initialize(appLanguage);

            // Ensures console supports UTF-8 output.
            Console.OutputEncoding = Encoding.UTF8;

            // Cancellation token for accept loop and background tasks.
            _acceptCts = new CancellationTokenSource();
            CancellationToken token = _acceptCts.Token;

            // Graceful Ctrl+C shutdown.
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                _exitByCtrlC = true;
                Listener?.Stop();
                _acceptCts.Cancel();
            };

            // Graceful shutdown on process exit using AppDomain.ProcessExit event because
            // it's triggered even when the process is killed by Task Manager or other means.
            AppDomain.CurrentDomain.ProcessExit += (s, e) =>
            {
                if (!_exitByCtrlC)
                {
                    Listener?.Stop();
                    _acceptCts.Cancel();
                }
            };

            // Display banner and prompt for port.
            DisplayBanner();
            int port = GetPortFromUser();
            _currentPort = port;

            try
            {
                // Initializes the Users list to ensure it's empty at startup.
                Users = new List<ServerConnectionHandler>();

                CreateAndStartListener(port);

                Console.WriteLine(string.Format(LocalizationManager.GetString("ServerStartedOnPort"), port));

                // Server is ready to accept commands from the console.
                Console.WriteLine(LocalizationManager.GetString("EnterCommandsBelow"));

                // Starts the async accept loop in the background with fire-and-forget,
                // so it doesn't block the main thread.
                _ = RunAcceptLoopAsync(_acceptCts.Token);

                // Runs the console command loop on the main thread.
                // This loop uses Console.ReadLine(), which is blocking by nature.
                // It must stay on the main thread to avoid deadlocks so we use a synchronous wait.
                RunCommandLoopAsync(_acceptCts.Token).Wait();

                // Once the command loop exits (shutdown command), performs cleanup.
                // A fresh cancellation token is used so shutdown is not cancelled prematurely.
                using var shutdownCts = new CancellationTokenSource();
                
                await ShutdownAsync(shutdownCts.Token).ConfigureAwait(false);
            }

            catch (Exception ex)
            {
                Console.WriteLine(string.Format(LocalizationManager.GetString("ServerStartFailed"),
                        port, ex.Message));

                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Broadcasts a DisconnectNotify to all remaining clients.
        /// Does not modify the Users list; caller must remove the user beforehand.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for async operations.</param>
        /// <param name="disconnectedUserId">The UID of the user who disconnected.</param>
        /// <param name="username">The username of the user who disconnected (can be null or empty).</param>
        public static async Task BroadcastDisconnectNotify(Guid disconnectedUserId, string username,
            CancellationToken cancellationToken)
        {
            // Fallback username
            if (string.IsNullOrWhiteSpace(username))
            {
                username = "(unknown)";
            }

            // Snapshot of current users
            List<ServerConnectionHandler> snapshot;
            lock (Users)
            {
                snapshot = Users.ToList();
            }

            var sendTasks = new List<Task>();

            foreach (var usr in snapshot)
            {
                if (!usr.ClientSocket.Connected)
                {
                    continue;
                }

                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)PacketOpCode.DisconnectNotify);
                builder.WriteUid(disconnectedUserId);
                builder.WriteString(username);

                byte[] payload = builder.GetPacketBytes();

                var task = Task.Run(async () =>
                {
                    try
                    {
                        await SendFramedAsync(usr, payload, cancellationToken).ConfigureAwait(false);
                        ServerLogger.LogLocalized("DisconnectNotifySuccess", ServerLogLevel.Debug, usr.Username);
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("DisconnectNotifyFailed", ServerLogLevel.Warn, usr.Username, ex.Message);
                    }
                }, cancellationToken);

                sendTasks.Add(task);
            }

            try
            {
                await Task.WhenAll(sendTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            { }

            ServerLogger.LogLocalized("UserDisconnected", ServerLogLevel.Info, username);
        }

        /// <summary>
        /// Builds and sends a framed ForceDisconnectClient packet to every connected client.  
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
        /// Broadcasts a PublicKeyResponse packet to all connected clients.
        /// </summary>
        /// <param name="originUid">The UID of the user whose public key is being broadcasted.</param>
        /// <param name="publicKey">The public key bytes to broadcast.</param>
        /// <param name="cancellationToken">The cancellation token for async operations.</param>
        /// <returns></returns>
        public static async Task BroadcastNewPublicKeyAsync(Guid originUid, byte[] publicKey, CancellationToken cancellationToken)
        {
            var snapshotUsers = Users.ToList();

            // Prepares a list of tasks to send the PublicKeyResponse to all connected clients.
            var sendTasks = new List<Task>(snapshotUsers.Count);

            foreach (var targetUser in snapshotUsers)
            {
                if (!targetUser.ClientSocket.Connected)
                {
                    continue;
                }

                var publicKeyPacket = new PacketBuilder();
                publicKeyPacket.WriteOpCode((byte)PacketOpCode.PublicKeyResponse);
                publicKeyPacket.WriteUid(originUid);
                publicKeyPacket.WriteBytesWithLength(publicKey);
                publicKeyPacket.WriteUid(targetUser.UID);

                byte[] payload = publicKeyPacket.GetPacketBytes();

                var sendTask = Task.Run(async () =>
                {
                    try
                    {
                        await SendFramedAsync(targetUser, payload, cancellationToken).ConfigureAwait(false);
                        ServerLogger.LogLocalized("PublicKeyRelaySuccess", ServerLogLevel.Debug, targetUser.Username);
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("PublicKeyRelayFailed", ServerLogLevel.Warn, targetUser.Username, ex.Message);
                    }
                }, cancellationToken);

                sendTasks.Add(sendTask);
            }

            try
            {
                // WhenAll will wait for all tasks to finish
                await Task.WhenAll(sendTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            { }
        }

        /// <summary>
        /// Broadcasts a plain text message to all connected clients.
        /// </summary>
        /// <param name="messageText"></param>
        /// <param name="senderUid"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public static async Task BroadcastPlainMessage(string messageText, Guid senderUid, CancellationToken cancellationToken)
        {
            var snapshotUsers = Users.ToList();
            var sendTasks = new List<Task>(snapshotUsers.Count);

            foreach (var target in snapshotUsers)
            {
                if (!target.ClientSocket.Connected)
                    continue;

                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)PacketOpCode.PlainMessage);
                builder.WriteUid(senderUid);
                builder.WriteUid(target.UID);
                builder.WriteString(messageText);

                byte[] payload = builder.GetPacketBytes();

                ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

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
        /// Broadcasts the full roster of connected users to every client.
        /// </summary>
        public static async Task BroadcastRosterAsync(CancellationToken cancellationToken = default)
        {
            var snapshotUsers = Users.ToList();

            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)PacketOpCode.RosterBroadcast);
            builder.WriteInt32NetworkOrder(snapshotUsers.Count);

            foreach (var target in snapshotUsers)
            {
                builder.WriteUid(target.UID);
                builder.WriteString(target.Username);
                byte[] publicKeyInBytes = target.PublicKeyDer ?? Array.Empty<byte>();
                builder.WriteBytesWithLength(publicKeyInBytes);
            }

            byte[] payload = builder.GetPacketBytes();

            ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

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

            try
            {
                await Task.WhenAll(sendTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            
            }
        }

        /// <summary>
        /// Produces a compact UID representation: xxxx-xxxx-xxxx-xxxx (first 4 blocks).
        /// </summary>
        /// <param name="uid">The full GUID to compact.</param>
        private static string CompactUid(Guid uid)
        {
            string fullUid = uid.ToString();
            string[] partsOfUid = fullUid.Split('-');
            
            if (partsOfUid.Length >= 4)
            {
                // Returns the first 4 blocks of the GUID, joined by hyphens.
                return string.Join('-', partsOfUid.Take(4));
            }

            // If the GUID format is unexpected, return the full string as a fallback.
            return fullUid;
        }

        /// <summary>
        /// Creates and starts the TCP listener on the current port.
        /// </summary>
        private static void CreateAndStartListener(int port)
        {
            Listener?.Stop();

            // Creates a new listener bound to localhost and the specified port.
            Listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
            Listener.Start();
            AcceptingClients = true;
        }


        static void DisplayBanner()
        {
            Console.WriteLine("╔═══════════════════════════════════╗");
            Console.WriteLine("║          Chat Server 1.1          ║");
            Console.WriteLine("╚═══════════════════════════════════╝");
            Console.WriteLine(LocalizationManager.GetString("BannerLine1"));
            Console.WriteLine(LocalizationManager.GetString("BannerLine2"));
        }

        static int GetPortFromUser()
        {
            int defaultPort = 7123;
            int chosenPort = defaultPort;

            Console.WriteLine(LocalizationManager.GetString("PortPrompt"));
            string input = ReadLineWithTimeout(7000);

            if (!string.IsNullOrWhiteSpace(input))
            {
                if (int.TryParse(input, out int port) && port >= 1000 && port <= 65535)
                {
                    chosenPort = port;
                }
                else
                {
                    Console.WriteLine(LocalizationManager.GetString("InvalidPortPrompt"));
                    string confirmRaw = ReadLineWithTimeout(7000);
                    string confirm = (confirmRaw ?? string.Empty).Trim().ToLowerInvariant();

                    if (confirm == "y")
                    {
                        chosenPort = defaultPort;
                    }
                    else
                    {
                        Console.WriteLine(LocalizationManager.GetString("Exiting"));
                        Environment.Exit(0);
                    }
                }
            }

            return chosenPort;
        }

        /// <summary>
        /// Handles kick/raus commands. Supports username (case-insensitive) and UID.
        /// If multiple users share the same username, asks to use UID.
        /// The alias 'raus <uid>' exists but is not documented in error messages.
        /// </summary>
        private static async Task HandleKickCommandAsync(string command, string argument, CancellationToken token)
        {
            if (string.IsNullOrWhiteSpace(argument))
            {
                Console.WriteLine(LocalizationManager.GetString("KickUsage"));
                ServerLogger.Log("Kick command missing argument.", ServerLogLevel.Warn);
                return;
            }

            argument = argument.Trim();

            // Tries parse as GUID first.
            if (Guid.TryParse(argument, out Guid parsedUid))
            {
                ServerConnectionHandler? targetByUid;

                // lock the Users list to safely search for the user by UID
                lock (Users)
                {
                    targetByUid = Users.FirstOrDefault(user => user.UID == parsedUid);
                }

                if (targetByUid == null)
                {
                    Console.WriteLine(LocalizationManager.GetString("NoUserFoundWithThisUid"));
                    ServerLogger.Log($"Kick by UID failed: {parsedUid}", ServerLogLevel.Warn);
                    return;
                }

                ServerLogger.LogLocalized("KickByUid", ServerLogLevel.Info, targetByUid.Username, parsedUid.ToString());

                // Closes the connection from the server side.
                targetByUid.ForceCloseFromServer();
                return;
            }

            // Otherwise, treats as username (case-insensitive).
            List<ServerConnectionHandler> userMatches;

            lock (Users)
            {
                // Finds all users with the matching username (case-insensitive).
                userMatches = Users
                    .Where(user => string.Equals(user.Username, argument, StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }

            if (userMatches.Count == 0)
            {
                Console.WriteLine(LocalizationManager.GetString("NoUserFoundWithUsername"));
                ServerLogger.Log($"Kick by username failed: {argument}", ServerLogLevel.Warn);
                return;
            }

            if (userMatches.Count > 1)
            {
                Console.WriteLine(LocalizationManager.GetString("UsernameAmbiguousUseUid"));
                ServerLogger.Log($"Kick ambiguous username: {argument}", ServerLogLevel.Warn);
                return;
            }

            var targetUser = userMatches[0];
            ServerLogger.LogLocalized("KickByUsername", ServerLogLevel.Info, targetUser.Username, targetUser.UID.ToString());

            targetUser.ForceCloseFromServer();

            // Waits briefly to ensure the disconnect packet is sent before returning.
            await Task.CompletedTask;
        }

        /// <summary>
        /// Handles limit/max commands. Changes MaxClients for future connections only.
        /// Existing clients are not disconnected.
        /// </summary>
        /// <param name="arg">The new limit value as a string. If empty, prints the current limit.</param>
        private static void HandleLimitCommand(string arg)
        {
            if (string.IsNullOrWhiteSpace(arg))
            {
                Console.WriteLine(string.Format(LocalizationManager.GetString("CurrentLimit"), MaxClients));
                ServerLogger.Log($"Limit command queried current value: {MaxClients}", ServerLogLevel.Info);
                return;
            }

            if (!int.TryParse(arg.Trim(), out int newLimit) || newLimit <= 0)
            {
                Console.WriteLine(LocalizationManager.GetString("InvalidLimitValue"));
                ServerLogger.Log($"Limit command invalid value: {arg}", ServerLogLevel.Warn);
                return;
            }

            MaxClients = newLimit;
            Console.WriteLine(string.Format(LocalizationManager.GetString("MaxClientsLimitSet"), MaxClients));
            ServerLogger.Log($"Max clients limit changed to {MaxClients}.", ServerLogLevel.Info);
        }

        /// <summary>
        /// Handles list/lst/users command: prints connected users in compact format.
        /// UID: xxxx-xxxx-xxxx-xxxx | username: X | IP: A.B.C.D:Port | On since: 01h 02m 30s
        /// </summary>
        private static void HandleListCommand()
        {
            List<ServerConnectionHandler> usersSnapshot;
            
            lock (Users)
            {
                usersSnapshot = Users.ToList();
            }

            if (usersSnapshot.Count == 0)
            {
                Console.WriteLine(LocalizationManager.GetString("NoUsersConnected"));
                ServerLogger.Log("List command: no users connected.", ServerLogLevel.Info);
                return;
            }

            foreach (var usr in usersSnapshot)
            {
                string userUidCompact = CompactUid(usr.UID);
                string username = string.IsNullOrWhiteSpace(usr.Username) ? "(unknown)" : usr.Username;

                string userIpAddress = "(unknown)";
                
                try
                {
                    if (usr.ClientSocket?.Client?.RemoteEndPoint is IPEndPoint endPoint)
                    {
                        userIpAddress = $"{endPoint.Address}:{endPoint.Port}";
                    }
                }
                catch { }

                string userConnectedSince = usr.GetConnectedSinceDurationString();

                Console.WriteLine(string.Format(LocalizationManager.GetString("ListUserEntry"), 
                    userUidCompact, username, userIpAddress, userConnectedSince));

            }

            ServerLogger.Log($"List command: {usersSnapshot.Count} users listed.", ServerLogLevel.Info);
        }


        /// <summary>
        /// Handles startAccepting command: recreates listener and restarts accept loop.
        /// </summary>
        private static void HandleStartAcceptingCommand()
        {
            if (Listener != null)
            {
                Console.WriteLine(LocalizationManager.GetString("ListenerAlreadyRunning"));
                ServerLogger.Log("startAccepting called but listener already running.", ServerLogLevel.Debug);
                return;
            }

            CreateAndStartListener(_currentPort);
            Console.WriteLine(LocalizationManager.GetString("ListenerStartedAccepting"));
            ServerLogger.Log("Listener started via startAccepting command.", ServerLogLevel.Info);
        }

        /// <summary>
        /// Handles stopAccepting command: stops listener and prevents new connections.
        /// </summary>
        private static void HandleStopAcceptingCommand()
        {
            if (Listener == null)
            {
                Console.WriteLine(LocalizationManager.GetString("ListenerNotRunning"));
                ServerLogger.Log("stopAccepting called but listener is null.", ServerLogLevel.Debug);
                return;
            }

            AcceptingClients = false;

            // Cleanly breaks AcceptTcpClientAsync without freezing the thread.
            Listener.Stop();
            Listener = null;

            Console.WriteLine(LocalizationManager.GetString("ListenerStopped"));
            ServerLogger.Log("Listener stopped via stopAccepting command.", ServerLogLevel.Info);
        }

        /// <summary>
        /// Handles shutdown command: triggers global shutdown.
        /// </summary>
        private static void HandleShutdownCommand()
        {
            Console.WriteLine(LocalizationManager.GetString("ShutdownRequested"));
            ServerLogger.Log("Shutdown command received.", ServerLogLevel.Info);

            Listener?.Stop();
            _acceptCts.Cancel();
        }

        private static void PrintHelpPanel()
        {
            Console.WriteLine();
            Console.WriteLine("+----------------------------------------------+");
            Console.WriteLine("|                 SERVER COMMANDS              |");
            Console.WriteLine("+----------------------------------------------+");
            Console.WriteLine("| list           : Show connected users        |");
            Console.WriteLine("| kick           : Disconnect a user           |");
            Console.WriteLine("| limit          : Set maximum client count    |");
            Console.WriteLine("| startaccepting : Allow new connections       |");
            Console.WriteLine("| stopaccepting  : Block new connections       |");
            Console.WriteLine("| shutdown       : Stop server gracefully      |");
            Console.WriteLine("| help or ?      : Show this help panel        |");
            Console.WriteLine("+----------------------------------------------+");
            Console.WriteLine("| Notes:                                       |");
            Console.WriteLine("|  - Commands are case-insensitive             |");
            Console.WriteLine("|  - Aliases exist, also in French and Spanish |");
            Console.WriteLine("+----------------------------------------------+");
            Console.WriteLine();
        }


        /// <summary>
        /// Reads a line from the console with a specified timeout.
        /// </summary>
        /// <param name="timeoutMs"></param>
        /// <returns>A string containing the line read, or an empty string if the timeout is reached.</returns>
        static string ReadLineWithTimeout(int timeoutMs)
        {
            var task = Task.Run(() => Console.ReadLine());

            if (task.Wait(timeoutMs))
            {
                return task.Result ?? string.Empty;
            }

            return string.Empty;
        }

        /// <summary>
        /// Relays an encrypted message from one user to another.
        /// </summary>
        /// <param name="ciphertext">Encrypted message bytes to relay.</param>
        /// <param name="senderUid">Sender UID.</param>
        /// <param name="recipientUid">Recipient UID.</param>
        /// <param name="cancellationToken">Cancellation token for async operations.</param>
        /// <returns></returns>
        public static async Task RelayEncryptedMessageToAUser(byte[] ciphertext, Guid senderUid,
            Guid recipientUid, CancellationToken cancellationToken)
        {
            var recipient = Users.FirstOrDefault(user => user.UID == recipientUid);

            if (recipient?.ClientSocket == null || recipient.ClientSocket.Connected != true)
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn,
                    recipientUid.ToString(), "Recipient not connected");
                return;
            }

            if (!recipient.IsEstablished)
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn,
                    recipientUid.ToString(), "Recipient not established");
                return;
            }

            if (ciphertext == null || ciphertext.Length == 0)
            {
                ServerLogger.LogLocalized("ErrorEmptyCiphertext", ServerLogLevel.Warn,
                    senderUid.ToString(), recipientUid.ToString());
                return;
            }

            var encMsgPacket = new PacketBuilder();
            encMsgPacket.WriteOpCode((byte)PacketOpCode.EncryptedMessage);
            encMsgPacket.WriteUid(senderUid);
            encMsgPacket.WriteUid(recipientUid);
            encMsgPacket.WriteBytesWithLength(ciphertext);

            var payloadInBytes = encMsgPacket.GetPacketBytes();

            try
            {
                await SendFramedAsync(recipient, payloadInBytes, cancellationToken).ConfigureAwait(false);
                ServerLogger.LogLocalized("EncryptedMessageRelaySuccess", ServerLogLevel.Debug, recipient.Username);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("EncryptedMessageRelayFailed", ServerLogLevel.Warn,
                    recipient.Username, ex.Message);
            }
        }

        /// <summary>
        /// Relays a PublicKeyRequest from one user to another. 
        /// The target user will receive a PublicKeyRequest packet containing the requester's UID.
        /// </summary>
        /// <param name="requesterUid">The UID of the user requesting the public key.</param>
        /// <param name="targetUid">The UID of the user whose public key is being requested.</param>
        /// <param name="cancellationToken">The cancellation token for async operations.</param>
        /// <returns></returns>
        public static async Task RelayPublicKeyRequest(Guid requesterUid, Guid targetUid, CancellationToken cancellationToken)
        {
            var snapshotUsers = Users.ToList();
            var targetUser = snapshotUsers.FirstOrDefault(user => user.UID == targetUid);

            if (targetUser?.ClientSocket?.Connected != true)
            {
                return;
            }

            if (!targetUser.IsEstablished)
            {
                ServerLogger.LogLocalized("PublicKeyRequestRelayFailed", ServerLogLevel.Warn,
                    targetUser?.Username ?? targetUid.ToString(), "Target not established");
                return;
            }

            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)PacketOpCode.PublicKeyRequest);
            builder.WriteUid(targetUid);
            builder.WriteUid(requesterUid);

            byte[] payload = builder.GetPacketBytes();
            ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}", ServerLogLevel.Debug);

            try
            {
                await SendFramedAsync(targetUser, payload, cancellationToken).ConfigureAwait(false);
                ServerLogger.LogLocalized("PublicKeyRequestRelaySuccess", ServerLogLevel.Debug, targetUser.Username);
            }
            
            catch (OperationCanceledException)
            {
            }
            
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("PublicKeyRequestRelayFailed", ServerLogLevel.Warn, targetUser.Username, ex.Message);
            }
        }

        /// <summary>
        /// Relays a PublicKeyResponse from one user to another.
        /// </summary>
        /// <param name="originUid">Origin Uid of the user whose public key is being relayed.</param>
        /// <param name="publicKey">Public key bytes to relay.</param>
        /// <param name="requesterUid">Uid of the user who requested the public key.</param>
        /// <param name="cancellationToken">Cancellation token for async operations.</param>
        /// <returns></returns>
        public static async Task RelayPublicKeyToUser(Guid originUid, byte[] publicKey, Guid requesterUid,
            CancellationToken cancellationToken)
        {
            var snapshotUsers = Users.ToList();
            var target = snapshotUsers.FirstOrDefault(usr => usr.UID == requesterUid);

            if (target == null || target.ClientSocket?.Connected != true)
            {
                ServerLogger.LogLocalized("PublicKeyResponseRelayFailed", ServerLogLevel.Warn,
                    requesterUid.ToString(), "Requester not connected");
                return;
            }

            if (!target.IsEstablished)
            {
                ServerLogger.LogLocalized("PublicKeyResponseRelayFailed",
                    ServerLogLevel.Warn, target.Username, "Requester not established");
                return;
            }

            var publicKeyResponsePacket = new PacketBuilder();
            publicKeyResponsePacket.WriteOpCode((byte)PacketOpCode.PublicKeyResponse);
            publicKeyResponsePacket.WriteUid(originUid);
            publicKeyResponsePacket.WriteBytesWithLength(publicKey ?? Array.Empty<byte>());
            publicKeyResponsePacket.WriteUid(requesterUid);

            byte[] payload = publicKeyResponsePacket.GetPacketBytes();

            // Logs the length and prefix of the payload for debugging purposes.
            ServerLogger.Log($"BUILDER_RETURNS_LEN={payload.Length} " +
                $"PREFIX={BitConverter.ToString(payload.Take(Math.Min(24, payload.Length)).ToArray())}",
                ServerLogLevel.Debug);

            try
            {
                // Sends the framed PublicKeyResponse packet to the target user.
                await SendFramedAsync(target, payload, cancellationToken).ConfigureAwait(false);
                ServerLogger.LogLocalized("PublicKeyResponseRelaySuccess", ServerLogLevel.Debug, target.Username);
            }
            
            catch (OperationCanceledException)
            {
            
            }
            
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("PublicKeyResponseRelayFailed", ServerLogLevel.Warn, target.Username, ex.Message);
            }
        }

        /// <summary>
        /// Main accept loop. 
        /// Accepts clients while AcceptingClients is true and the cancellation token is not requested. 
        /// When Listener is stopped, the loop exits gracefully.
        /// </summary>
        private static async Task RunAcceptLoopAsync(CancellationToken token)
        {
            // Accept loop cooperates with cancellation; no busy-wait or CPU spinning.
            while (!token.IsCancellationRequested)
            {
                if (!AcceptingClients || Listener == null)
                {
                    await Task.Delay(200, token).ConfigureAwait(false);
                    continue;
                }

                TcpClient tcpClient;

                try
                {
                    // Accepts a new TCP client asynchronously (non-blocking).
                    // This will wait until a client connects or the listener is stopped.
                    tcpClient = await Listener.AcceptTcpClientAsync().ConfigureAwait(false);
                }
                
                catch (ObjectDisposedException)
                {
                    // Listener stopped — exits loop.
                    break;
                }
                
                catch (Exception)
                {
                    await Task.Delay(100, token).ConfigureAwait(false);
                    continue;
                }

                // Enforces MaxClients limit for new connections.
                bool canAcceptNewClients;
                
                lock (Users)
                {
                    canAcceptNewClients = Users.Count < MaxClients;
                }

                if (!canAcceptNewClients)
                {
                    try
                    {
                        ServerLogger.Log("Connection refused: max clients limit reached.", ServerLogLevel.Warn);
                        tcpClient.Close();
                    }
                    
                    catch { }
                    continue;
                }

                // Handles accepted client on background task with a token for graceful cancellation.
                _ = Task.Run(async () =>
                {
                    // Initializes client as null so it can be referenced safely inside the catch block.
                    ServerConnectionHandler? clientConnectionHandler = null;

                    try
                    {
                        // Gets the network stream from the accepted TCP client.
                        var networkStream = tcpClient.GetStream();

                        // Reads 4-byte big-endian header.
                        byte[] header = await PacketReader.ReadExactAsync(networkStream, 4, token).ConfigureAwait(false);

                        // Reconstructs the payload length by interpreting the 4-byte header as a big-endian integer.
                        // Each byte is shifted into its correct position to rebuild the original 32-bit length value.
                        int payloadLength = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
                        
                        if (payloadLength <= 0 || payloadLength > 65_536)
                        {
                            tcpClient.Close();
                            return;
                        }

                        // Reads payload and parses handshake.
                        byte[] readPayload = await PacketReader.ReadExactAsync(networkStream, payloadLength, token).ConfigureAwait(false);
                        using var memoryStream = new MemoryStream(readPayload);
                        var packetReader = new PacketReader(memoryStream);

                        if ((ChatProtocol.Net.PacketOpCode)await packetReader.ReadByteAsync(token).ConfigureAwait(false) != PacketOpCode.Handshake)
                        {
                            tcpClient.Close();
                            return;
                        }

                        // Username of the connecting client
                        string username = await packetReader.ReadStringAsync(token).ConfigureAwait(false);
                        Guid uid = await packetReader.ReadUidAsync(token).ConfigureAwait(false);

                        // Reads and validates the public key from the handshake payload.
                        int publicKeyLength = await packetReader.ReadInt32NetworkOrderAsync(token).ConfigureAwait(false);
                        const int MaxPublicKeyLength = 65_536;
                        
                        if (publicKeyLength < 0 || publicKeyLength > MaxPublicKeyLength)
                        {
                            tcpClient.Close();
                            return;
                        }

                        byte[] publicKey = await PacketReader.ReadExactAsync(memoryStream, publicKeyLength, token).ConfigureAwait(false);

                        // Initializes client after handshake with the raw public key (can be empty).
                        // The instance is created only after handshake validation to avoid ghost clients.
                        clientConnectionHandler = new ServerConnectionHandler(tcpClient);

                        clientConnectionHandler.InitializeAfterHandshake(username, uid, publicKey, token);

                        lock (Users)
                        {
                            Users.RemoveAll(user => user.UID == uid);
                            Users.RemoveAll(user => user.Username == username);
                            Users.Add(clientConnectionHandler);
                        }

                        ServerLogger.LogLocalized("ClientConnected", ServerLogLevel.Info, username);

                        // Sends framed HandshakeAck.
                        var handshakeAckPacket = new PacketBuilder();
                        handshakeAckPacket.WriteOpCode((byte)PacketOpCode.HandshakeAck);
                        await SendFramedAsync(clientConnectionHandler, handshakeAckPacket.GetPacketBytes(), token).ConfigureAwait(false);

                        // Broadcasts roster after ack, so all clients get updated keys (empty keys included).
                        await BroadcastRosterAsync(token).ConfigureAwait(false);
                    }
                    
                    catch (OperationCanceledException)
                    {
                        tcpClient.Close();
                    }
                    
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("AcceptLoopClientError", ServerLogLevel.Warn, 
                            clientConnectionHandler?.Username ?? "(unknown)", ex.Message);
                        tcpClient.Close();
                    }
                }, token);
            }
        }

        /// <summary>
        /// Console command loop.
        /// This loop must run on its own thread because Console.ReadLine() is blocking.
        /// It cannot safely run inside an async context without risking deadlocks.
        /// </summary>
        private static Task RunCommandLoopAsync(CancellationToken token)
        {
            return Task.Run(() =>
            {
                while (!token.IsCancellationRequested)
                {
                    // Prompt for commands
                    Console.Write("> ");
                    
                    // Blocking call: must stay on a dedicated thread.
                    string? lineToRead = Console.ReadLine();

                    if (lineToRead == null)
                    {
                        // No input available, simply continue.
                        continue;
                    }

                    lineToRead = lineToRead.Trim();

                    if (string.IsNullOrWhiteSpace(lineToRead))
                    {
                        // Ignore empty commands.
                        continue;
                    }

                    ServerLogger.Log($"Command entered: {lineToRead}", ServerLogLevel.Info);

                    string[] partsOfLineToRead = lineToRead.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    string parsedCommand = partsOfLineToRead[0].ToLowerInvariant();
                    string argument = partsOfLineToRead.Length > 1
                        ? string.Join(' ', partsOfLineToRead.Skip(1))
                        : string.Empty;

                    switch (parsedCommand)
                    {
                        // Kick a user
                        case "kick":
                        case "raus":
                        case "virer":
                        case "expulser":
                        case "eject":
                        case "éjecter":
                        case "ejecter":
                        case "expulsar":
                        case "echar":
                            // Fire-and-forget: the command loop MUST remain synchronous.
                            // Kick is safe to run asynchronously because it only closes the user's socket.
                            // Any follow-up (disconnect broadcast, cleanup) is handled internally.
                            _ = HandleKickCommandAsync(parsedCommand, argument, token);
                            break;

                        // Limit max number of connected users
                        case "limit":
                        case "limite":
                        case "max":
                        case "maximum":
                            HandleLimitCommand(argument);
                            break;

                        // Start accepting new clients
                        case "start":
                        case "startaccept":
                        case "startaccepting":
                        case "startacceptclients":
                        case "startacceptingclients":
                        case "startacceptnewclients":
                        case "startacceptingnewclients":
                        case "accept":
                        case "accepter":
                        case "aceptar":
                        case "demarrer":
                        case "démarrer":
                        case "reprendre":
                            HandleStartAcceptingCommand();
                            break;

                        // Stop accepting new clients
                        case "stop":
                        case "stopaccept":
                        case "stopaccepting":
                        case "stopacceptclients":
                        case "stopacceptingclients":
                        case "blockaccept":
                        case "blocknew":
                        case "blocknewclients":
                        case "complet":
                        case "full":
                        case "pausar":
                        case "pause":
                            HandleStopAcceptingCommand();
                            break;

                        // Shutdown the server
                        case "shutdown":
                        case "exit":
                        case "quit":
                        case "q":
                        case "close":
                        case "fin":
                        case "terminer":
                        case "arreter":
                        case "arrêter":
                        case "fermer":
                        case "quitter":
                        case "apagar":
                        case "cerrar":
                        case "detener":
                            HandleShutdownCommand();
                            return; // Exit the command loop thread.

                        // List connected users
                        case "ls":
                        case "list":
                        case "users":
                        case "utilisateurs":
                        case "usuarios":
                        case "liste":
                        case "lista":
                        case "clients":
                        case "connected":
                        case "connectedclients":
                        case "connectedusers":
                        case "listclients":
                        case "listusers":
                        case "listconnected":
                        case "listconnectedclients":
                        case "listconnectedusers":
                            HandleListCommand();
                            break;

                        // Help panel
                        case "?":
                        case "help":
                        case "aide":
                        case "ayuda":
                            PrintHelpPanel();
                            break;

                        default:
                            Console.WriteLine(LocalizationManager.GetString("UnknownCommand"));
                            ServerLogger.Log($"Unknown command: {parsedCommand}", ServerLogLevel.Warn);
                            break;
                    }
                }
            });
        }

        /// <summary>
        /// Sends a framed payload to a recipient. The payload is prefixed with a 4-byte big-endian length header.
        /// </summary>
        /// <param name="recipientConnectionHandler">The recipient ServerConnectionHandler to send the payload to.</param>
        /// <param name="payload">The payload bytes to send.</param>
        /// <param name="cancellationToken">Cancellation token for async operations.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="IOException"></exception>
        public static async Task SendFramedAsync(ServerConnectionHandler recipientConnectionHandler, byte[] payload, CancellationToken cancellationToken = default)
        {
            if (recipientConnectionHandler == null)
            {
                throw new ArgumentNullException(nameof(recipientConnectionHandler));
            }

            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            // Each client has its own semaphore so that only one send operation can run at a time.
            // This prevents two threads from writing to the same NetworkStream simultaneously,
            // which would corrupt the length‑prefixed framing.
            // The semaphore is retrieved (or created if missing) from a dictionary keyed by the client's UID.
            // Once the send is finished, the semaphore is released so the next send can proceed safel
            var sem = _sendSemaphores.GetOrAdd(recipientConnectionHandler.UID, _ => new SemaphoreSlim(1, 1));
            await sem.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                var tcpSocket = recipientConnectionHandler.ClientSocket;
                var networkStream = tcpSocket?.GetStream();

                if (networkStream == null || tcpSocket?.Connected != true)
                {
                    throw new IOException("Recipient NetworkStream is unavailable or socket not connected.");
                }

                int payloadLength = payload.Length;
                byte[] headerByte = new byte[4];
                headerByte[0] = (byte)(payloadLength >> 24);
                headerByte[1] = (byte)(payloadLength >> 16);
                headerByte[2] = (byte)(payloadLength >> 8);
                headerByte[3] = (byte)payloadLength;

                ServerLogger.Log($"OUTGOING_FRAME_HEADER={BitConverter.ToString(headerByte)} LEN={payload.Length}", ServerLogLevel.Debug);
                ServerLogger.Log($"BUILT_PAYLOAD_LEN={payload.Length}", ServerLogLevel.Debug);

                int prefixLength = Math.Min(16, payload.Length);
                if (prefixLength > 0)
                {
                    var prefixBytes = new byte[prefixLength];
                    Array.Copy(payload, 0, prefixBytes, 0, prefixLength);
                    ServerLogger.Log($"OUTGOING_FRAME_PAYLOAD_PREFIX={BitConverter.ToString(prefixBytes)}", ServerLogLevel.Debug);
                }

                try
                {
                    // WriteAsync is fully asynchronous; no thread blocking during network I/O.
                    await networkStream.WriteAsync(headerByte, 0, headerByte.Length, cancellationToken).ConfigureAwait(false);

                    if (payload.Length > 0)
                    {
                        await networkStream.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                    }

                    // FlushAsync ensures immediate delivery without blocking the thread.
                    await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                
                catch (IOException ioEx)
                {
                    ServerLogger.LogLocalized("SendFramedIoError", ServerLogLevel.Warn, recipientConnectionHandler.Username ?? recipientConnectionHandler.UID.ToString(), ioEx.Message);
                    throw;
                }
            }
            
            finally
            {
                sem.Release();
            }
        }

        /// <summary>
        /// Stop accepting new clients, disconnects all connected users 
        /// and cleans up resources to prepare for server shutdown.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public static async Task ShutdownAsync(CancellationToken cancellationToken)
        {
            Console.WriteLine(LocalizationManager.GetString("ServerShutdown"));

            Listener?.Stop();
            _acceptCts?.Cancel();

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

            // Waits briefly to ensure all disconnect packets are sent before closing sockets.
            await Task.Delay(100, cancellationToken).ContinueWith(_ => { });

            lock (Users)
            {
                // Disposes all client sockets to ensure proper cleanup of resources.
                foreach (var usr in Users.ToList())
                {
                    usr.ClientSocket?.Dispose();
                }
                
                Users.Clear();
            }

            // Cleans up the send cancellation token sources to avoid memory leaks.
            _acceptCts?.Dispose();
            _acceptCts = new CancellationTokenSource();

            Console.WriteLine(LocalizationManager.GetString("ServerShutdownComplete"));
        }
    }
}
