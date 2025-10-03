/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 4th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;    // for ManualResetEventSlim

namespace chat_server
{
    /// <summary>
    /// Serves as the application entry point.
    /// Configures console encoding, registers shutdown handlers,
    /// initializes localization, prompts for a listening port,
    /// instantiates the TCP listener on that port, and starts the client-accept loop.
    /// </summary>
    public class Program
    {
        // Holds the server’s TCP listener instance; is instantiated before use.
        private static TcpListener _listener = default!;

        // Used to block the Main thread until a shutdown is requested.
        private static readonly ManualResetEventSlim _shutdownEvent = new(false);

        public static readonly List<Client> Users = new();
        public static string AppLanguage = "en";
        public static readonly Guid SystemUID =
            Guid.Parse("00000000-0000-0000-0000-000000000001");

        /// <summary>
        /// Serves as the application entry point.
        /// Sets up console encoding, installs Ctrl+C handler,
        /// initializes localization, displays the banner,
        /// prompts for the server port, creates the listener,
        /// and launches client-accept logic.
        /// </summary>
        public static void Main(string[] args)
        {
            // Configures the console to use UTF-8 encoding.
            Console.OutputEncoding = Encoding.UTF8;

            // Registers a handler to perform a graceful shutdown on Ctrl+C.
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;             // Prevent immediate process termination
                Shutdown();                  // Notify all clients and clean up
                _shutdownEvent.Set();        // Unblock the Main thread
            };

            // Determines system language and initializes localization.
            string systemCulture = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            AppLanguage = systemCulture == "fr" ? "fr" : "en";
            LocalizationManager.Initialize(AppLanguage);

            // Displays the localized startup banner.
            DisplayBanner();

            // Prompts the administrator to enter the TCP listening port.
            int portToListenTo = GetPortFromUser();

            try
            {
                // Instantiates the TCP listener on the specified port.
                _listener = new TcpListener(IPAddress.Any, portToListenTo);

                // Starts listening for incoming client connections.
                StartServerListener(portToListenTo);

                // Blocks the main thread until a shutdown signal is received.
                _shutdownEvent.Wait();
            }
            catch (Exception ex)
            {
                // Logs failure to start the listener on the chosen port.
                ServerLogger.LogLocalized(
                    $"{LocalizationManager.GetString("ServerStartFailed")} {portToListenTo}: {ex.Message}",
                    ServerLogLevel.Error);

                // Logs that the application is exiting and then terminates.
                ServerLogger.LogLocalized(
                    LocalizationManager.GetString("Exiting"),
                    ServerLogLevel.Info);

                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Broadcasts the complete roster to each connected client except the sender.
        /// Constructs a ConnectionBroadcast packet for each user entry and dispatches it.
        /// Logs a single completion message for recruiter-ready documentation.
        /// </summary>
        public static void BroadcastConnection()
        {
            // Iterates through every recipient in the user list
            foreach (var receiver in Users)
            {
                // Iterates through every user to include in the roster
                foreach (var usr in Users)
                {
                    // Skips sending the roster entry back to its origin
                    if (receiver.UID == usr.UID)
                        continue;

                    // Constructs the ConnectionBroadcast packet with UID, username, and public key
                    var broadcastConnectionPacket = new PacketBuilder();
                    broadcastConnectionPacket.WriteOpCode((byte)ServerPacketOpCode.ConnectionBroadcast);
                    broadcastConnectionPacket.WriteUid(usr.UID);
                    broadcastConnectionPacket.WriteString(usr.Username);
                    broadcastConnectionPacket.WriteString(usr.PublicKeyBase64 ?? string.Empty);

                    // Sends the serialized packet to the recipient’s socket
                    receiver.ClientSocket.Client
                        .Send(broadcastConnectionPacket.GetPacketBytes());
                }
            }

            // Logs only once when the full roster broadcast completes
            ServerLogger.Log(
                "[SERVER] Completed user list broadcast",
                ServerLogLevel.Debug);
        }

        /// <summary>Notifies clients of a disconnection (opcode 10) and logs each send.</summary>
        public static void BroadcastDisconnect(string uid)
        {
            var disconnectedUser = Users.FirstOrDefault(u => u.UID.ToString() == uid);
            if (disconnectedUser == null)
                return;

            foreach (var user in Users)
            {
                try
                {
                    var broadcastDisconnectPacket = new PacketBuilder();
                    broadcastDisconnectPacket.WriteOpCode((byte)ServerPacketOpCode.DisconnectNotify);
                    broadcastDisconnectPacket.WriteUid(Guid.Parse(uid));   // replaced WriteMessage(uid)

                    if (user.ClientSocket.Connected)
                    {
                        byte[] packetBytes = broadcastDisconnectPacket.GetPacketBytes();
                        user.ClientSocket.GetStream()
                            .Write(packetBytes, 0, packetBytes.Length);
                    }

                    ServerLogger.Log($"[SERVER] Notified {user.Username} of disconnection", ServerLogLevel.Debug);
                }
                catch (Exception ex)
                {
                    ServerLogger.Log($"[SERVER] Disconnect notification failed: {ex.Message}", ServerLogLevel.Error);
                }
            }
        }

        /// <summary>
        /// Dispatches a chat message packet (opcode 5) to a single recipient or to all connected clients.
        /// Ensures reliable routing, detailed logging for audit, and proper network transmission to each client.
        /// </summary>
        public static void BroadcastMessage(string rawMessageContent, Guid senderId, Guid recipientId)
        {
            // Retrieves the sender’s user model from the active user list
            var sendingUser = Users.FirstOrDefault(u => u.UID == senderId);
            string sendingUserName = sendingUser?.Username ?? "Unknown";

            // Prepares a masked version for logging if the message is encrypted
            string displayMessageContent = rawMessageContent.StartsWith("[ENC]")
                ? "[Encrypted]"
                : rawMessageContent;

            // Formats the current timestamp for inclusion in debug logs
            string currentTimestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            // Logs routing details: either a private message or a broadcast
            if (recipientId != Guid.Empty)
            {
                var targetUser = Users.FirstOrDefault(u => u.UID == recipientId);
                ServerLogger.Log($"[{currentTimestamp}] Message from {sendingUserName} to {targetUser?.Username ?? "Unknown"}: {displayMessageContent}", ServerLogLevel.Debug);
            }
            else
            {
                ServerLogger.Log($"[{currentTimestamp}] Broadcast message from {sendingUserName}: {displayMessageContent}", ServerLogLevel.Debug);
            }

            // Iterates through each connected user and sends the packet
            foreach (var user in Users)
            {
                // Skips users outside of the private message’s recipient
                if (recipientId != Guid.Empty && user.UID != recipientId)
                    continue;

                try
                {
                    // Builds the PlainMessage packet with sender, recipient, and content
                    var messagePacket = new PacketBuilder();
                    messagePacket.WriteOpCode((byte)ServerPacketOpCode.PlainMessage);
                    messagePacket.WriteUid(senderId);
                    messagePacket.WriteUid(recipientId);
                    messagePacket.WriteString(rawMessageContent);

                    // Writes the packet bytes to the user’s network stream if still connected
                    if (user.ClientSocket.Connected)
                    {
                        var networkStream = user.ClientSocket.GetStream();
                        byte[] packetBytes = messagePacket.GetPacketBytes();
                        networkStream.Write(packetBytes, 0, packetBytes.Length);
                    }
                }
                catch (Exception ex)
                {
                    // Logs any transmission failure per user for post-mortem analysis
                    ServerLogger.Log($"[SERVER] Failed sending message to {user.Username}: {ex.Message}",
                        ServerLogLevel.Debug);
                }
            }
        }

        /// <summary>Distributes sender's public key (opcode 6) to other clients.</summary>
        public static void BroadcastPublicKeyToOthers(Client sender)
        {
            foreach (var user in Users)
            {
                if (user.UID == sender.UID) continue;
                try
                {
                    var broadcastPublicKeyPacket = new PacketBuilder();
                    broadcastPublicKeyPacket.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
                    broadcastPublicKeyPacket.WriteUid(sender.UID);
                    broadcastPublicKeyPacket.WriteString(sender.PublicKeyBase64!);
                    if (user.ClientSocket.Connected)
                        user.ClientSocket.GetStream()
                            .Write(broadcastPublicKeyPacket.GetPacketBytes(), 0, broadcastPublicKeyPacket.GetPacketBytes().Length);

                    ServerLogger.Log($"[SERVER] Transmitted public key from {sender.Username} to {user.Username}", ServerLogLevel.Debug);
                }
                catch (Exception ex)
                {
                    ServerLogger.Log($"[SERVER] Public key transmission failed: {ex.Message}", ServerLogLevel.Error);
                }
            }
            ServerLogger.Log("[SERVER] Completed public key broadcast", ServerLogLevel.Debug);
        }

        /// <summary>Displays the localized startup banner.</summary>
        private static void DisplayBanner()
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

            // Prints the prompt without newline and leaves a space for input
            Console.Write(LocalizationManager.GetString("PortPrompt") + " ");

            // Read the user’s input
            string input = ReadLineWithTimeout(7000);


            if (!string.IsNullOrWhiteSpace(input))
            {
                // Validate port number
                if (int.TryParse(input, out int port) && port >= 1000 && port <= 65535)
                {
                    chosenPort = port;
                }
                else
                {
                    Console.Write(LocalizationManager.GetString("InvalidPortPrompt"));
                    string? confirm = Console.ReadLine()?.Trim().ToLower();

                    if (confirm == "y" || confirm == "o") // "o" for "oui" in French
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
        /// Handles a newly accepted TCP client:
        /// performs handshake, registers the client,
        /// broadcasts the roster, then starts its message loop.
        /// </summary>
        private static void HandleNewClient(TcpClient tcpClient)
        {
            // Logs the remote endpoint of the incoming connection
            var endpoint = tcpClient.Client.RemoteEndPoint?.ToString() ?? "Unknown endpoint";
            ServerLogger.Log($"Incoming connection from {endpoint}", ServerLogLevel.Info);

            // Obtains the network stream for this client
            NetworkStream stream = tcpClient.GetStream();

            // Reads one byte for the handshake opcode
            int opcode = stream.ReadByte();
            if (opcode < 0 || (ServerPacketOpCode)opcode != ServerPacketOpCode.Handshake)
            {
                ServerLogger.Log($"Invalid handshake opcode: {opcode}. Disconnecting.", ServerLogLevel.Error);
                tcpClient.Close();
                return;
            }

            // Parses the username, UID, and public key from the stream
            var reader = new PacketReader(stream);
            string username = reader.ReadString();
            Guid uid = reader.ReadUid();
            string publicKeyB64 = reader.ReadString();

            // Creates and registers the new client
            var client = new Client(tcpClient, username, uid)
            {
                PublicKeyBase64 = publicKeyB64
            };
            Users.Add(client);
            ServerLogger.Log($"Client connected: {username} ({uid})", ServerLogLevel.Info);

            // Broadcasts the updated roster to all clients
            BroadcastConnection();

            // Starts the message-listening loop for this client
            Task.Run(() => client.ListenForMessages());
        }


        /// <summary>Reads a console line with a timeout.</summary>
        private static string ReadLineWithTimeout(int timeoutMs)
        {
            string? result = "";
            Task.Run(() => result = Console.ReadLine()).Wait(timeoutMs);
            return result ?? string.Empty;
        }

        /// <summary>
        /// Gracefully shuts down the server by broadcasting a DisconnectClient packet  
        /// (opcode 12) to each connected client,
        /// then logs the initiation and completion of the shutdown sequence.
        /// </summary>
        public static void Shutdown()
        {
            ServerLogger.LogLocalized("ShutdownStart", ServerLogLevel.Info);

            foreach (var user in Users)
            {
                try
                {
                    var _packetBuilder = new PacketBuilder();
                    _packetBuilder.WriteOpCode(5);
                    _packetBuilder.WriteUid(SystemUID);          // replaced WriteMessage(uid)
                    _packetBuilder.WriteString("/disconnect");   // replaced WriteMessage("/disconnect")

                    if (user.ClientSocket.Connected)
                        user.ClientSocket.GetStream()
                            .Write(
                                _packetBuilder.GetPacketBytes(),
                                0,
                                _packetBuilder.GetPacketBytes().Length);
                }
                catch (Exception ex)
                {
                    ServerLogger.Log($"[SERVER] Shutdown notification failed: {ex.Message}", ServerLogLevel.Error);
                }
            }

            ServerLogger.LogLocalized("ShutdownComplete", ServerLogLevel.Info);
        }

        /// <summary>
        /// Starts the TCP listener and runs the client-accept loop in a background task.
        /// </summary>
        public static void StartServerListener(int port)
        {
            // Starts the pre-instantiated listener
            _listener.Start();
            Console.WriteLine();

            // Logs a localized “ServerStartedOnPort” message at Info level, formatting in the port
            ServerLogger.LogLocalized("ServerStartedOnPort", ServerLogLevel.Info, port);

            // Launches the accept loop in a background task
            Task.Run(async () =>
            {
                while (true)
                {
                    try
                    {
                        // Awaits an incoming TCP connection
                        TcpClient tcpClient = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);

                        // Delegates new-connection handling to helper
                        HandleNewClient(tcpClient);
                    }
                    catch (Exception ex)
                    {
                        // Logs accept-loop failures without crashing the server
                        ServerLogger.Log($"Accept loop failure: {ex.Message}", ServerLogLevel.Error);
                    }
                }
            });
        }
    }
}


