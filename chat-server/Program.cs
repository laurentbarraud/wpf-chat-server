/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

using chat_server.Net.IO;
using chat_server.Helpers;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace chat_server
{
    /// <summary>
    /// Entry point and coordinator for the server-side chat system.
    /// Manages the global list of connected clients and handles incoming connections via StartServerListener().
    /// Broadcasts user presence, messages, public keys, and disconnection events using opcode-based packets.
    /// Ensures protocol alignment and socket safety across all transmissions.
    /// Provides localized logging and error handling for traceability and debugging.
    /// </summary>
    public class Program
    {
        static TcpListener _listener; // TCP listener for incoming connections
        public static List<Client> _users = new List<Client>(); // Stores all connected clients

        /// <summary>
        /// Global language code used throughout the server ("en" or "fr")
        /// </summary>
        public static string AppLanguage = "en";

        /// <summary>
        /// Static UID used to represent system-originated messages (shutdown or server notices).
        /// This allows clients to distinguish between user and server messages.
        /// </summary>
        public static readonly Guid SystemUID = Guid.Parse("00000000-0000-0000-0000-000000000001");


        public static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            // Gracefully handle Ctrl+C to shut down the server
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Shutdown();
                Environment.Exit(0);
            };

            // Detects system language and initializes localization
            string systemCulture = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            AppLanguage = systemCulture == "fr" ? "fr" : "en";
            LocalizationManager.Initialize(AppLanguage);

            // Sets log verbosity based on build configuration or command-line flag
            #if DEBUG
                ServerLogger.IsDebugEnabled = true;
            #else
                ServerLogger.IsDebugEnabled = args.Contains("--debug");
            #endif

            // Displays localized banner
            DisplayBanner();

            // Prompts user for TCP port or use default
            int portToListenTo = GetPortFromUser();

            try
            {
                // Starts listening for incoming clients
                StartServerListener(portToListenTo);
            }
            catch (Exception ex)
            {
                // Displays error if server fails to start
                ServerLogger.LogLocalized($"\n{LocalizationManager.GetString("ServerStartFailed")} {portToListenTo}: {ex.Message}", LogLevel.Error);
                ServerLogger.LogLocalized(LocalizationManager.GetString("Exiting"), LogLevel.Info);
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Broadcasts the full list of connected users to every client.
        /// Uses opcode 1 to signal user presence and identity.
        /// For each receiver, iterates through all users and sends their UID, Username, and RSA public key.
        /// Ensures that every client receives a complete and synchronized view of the active user list.
        /// Logs each transmission for traceability and protocol validation.
        /// This method is central to client-side roster population and encryption readiness.
        /// </summary>
        public static void BroadcastConnection()
        {
            foreach (var receiver in _users)
            {
                foreach (var usr in _users)
                {
                    // Builds a user identity packet with opcode 1
                    var broadcastPacket = new PacketBuilder();
                    broadcastPacket.WriteOpCode(1); // Opcode for user connection
                    broadcastPacket.WriteMessage(usr.UID.ToString());        // First: UID
                    broadcastPacket.WriteMessage(usr.Username);              // Second: Username
                    broadcastPacket.WriteMessage(usr.PublicKeyBase64);       // Third: RSA public key

                    // Sends the packet to the current receiver
                    receiver.ClientSocket.Client.Send(broadcastPacket.GetPacketBytes());

                    // Logs the transmission for debugging and protocol validation
                    ServerLogger.Log("[SERVER] list of users broadcast:", LogLevel.Debug);
                    ServerLogger.Log($"         → Sent UID: {usr.UID}", LogLevel.Debug);
                    ServerLogger.Log($"         → Sent Username: {usr.Username}", LogLevel.Debug);
                    ServerLogger.Log($"         → Sent PublicKey: {usr.PublicKeyBase64.Substring(0, 30)}...", LogLevel.Debug);
                    ServerLogger.Log($"         → Receiver: {receiver.Username}", LogLevel.Debug);
                }
            }

            ServerLogger.Log("[SERVER] Full list of users broadcast completed.", LogLevel.Debug);
        }


        /// <summary>
        /// Notifies all connected users of a disconnection event.
        /// Removes the disconnected user from the global list and sends a disconnect packet to remaining clients.
        /// Uses opcode 10 to signal user departure.
        /// Wraps each transmission in a try/catch block to prevent socket exceptions.
        /// Logs each notification for traceability.
        /// </summary>
        /// <param name="uidDisconnected">The UID of the user who disconnected.</param>
        public static void BroadcastDisconnect(string uidDisconnected)
        {
            // Locates the disconnected user in the global list
            var disconnectedUser = _users.FirstOrDefault(x => x.UID.ToString() == uidDisconnected);

            if (disconnectedUser != null)
            {
                foreach (var user in _users)
                {
                    try
                    {
                        // Builds the disconnect packet with opcode 10
                        var packet = new PacketBuilder();
                        packet.WriteOpCode(10); // Disconnect opcode
                        packet.WriteMessage(uidDisconnected); // UID of disconnected user

                        // Sends the packet to each remaining client
                        if (user.ClientSocket.Connected)
                        {
                            user.ClientSocket.GetStream().Write(
                                packet.GetPacketBytes(),
                                0,
                                packet.GetPacketBytes().Length
                            );

                            ServerLogger.Log($"[SERVER] Sent disconnect notification to {user.Username} for UID {uidDisconnected}", LogLevel.Debug);
                        }
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.Log($"[SERVER] Failed to notify {user.Username} of disconnect: {ex.Message}", LogLevel.Debug);
                    }
                }
            }
        }

        /// <summary>
        /// Processes a chat packet with opcode 5.
        /// - When recipientUid is provided, it delivers the message only to the intended recipient.  
        ///   The sender is not echoed back with the encrypted packet, because the sender cannot decrypt it.  
        /// - When recipientUid is null, it delivers the message to all connected clients (broadcast).  
        /// Supports both plain-text and encrypted payloads (prefixed "[ENC]").  
        /// Logs each transmission with a timestamp for audit and debugging.
        /// </summary>
        /// <param name="content">
        /// The message content, either plain text or "[ENC]" + encrypted payload.
        /// </param>
        /// <param name="senderUid">
        /// UID of the client who originated the message.
        /// </param>
        /// <param name="recipientUid">
        /// Optional UID of the intended recipient.  
        /// Use null to broadcast to everyone.
        /// </param>
        public static void BroadcastMessage(string content, Guid senderUid, Guid? recipientUid = null)
        {
            foreach (var user in _users)
            {
                // In unicast mode, delivers only to the intended recipient
                if (recipientUid.HasValue && user.UID != recipientUid.Value)
                    continue;

                try
                {
                    // Builds the packet with [OpCode][SenderUid][RecipientUid or empty][Content]
                    var builder = new PacketBuilder();
                    builder.WriteOpCode(5);
                    builder.WriteMessage(senderUid.ToString());
                    builder.WriteMessage(recipientUid?.ToString() ?? string.Empty);
                    builder.WriteMessage(content);

                    byte[] packetBytes = builder.GetPacketBytes();

                    // Writes the packet to the client’s stream if still connected
                    if (user.ClientSocket.Connected)
                    {
                        user.ClientSocket.GetStream()
                            .Write(packetBytes, 0, packetBytes.Length);
                    }
                }
                catch (Exception ex)
                {
                    // Logs any exception encountered during send
                    ServerLogger.Log($"[SERVER] Failed to send to {user.Username}: {ex.Message}", LogLevel.Debug);
                }
            }

            // Resolves the sender’s username for logging
            var sender = _users.FirstOrDefault(u => u.UID == senderUid);
            string senderName = sender?.Username ?? "Unknown";

            // Prepares a human-readable display of the content
            string displayText = content.StartsWith("[ENC]") ? "[Encrypted]" : content;

            // Generates a timestamp for the log entry
            string timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");

            if (recipientUid.HasValue)
            {
                // In unicast mode, logs sender and recipient
                var recipient = _users.FirstOrDefault(u => u.UID == recipientUid.Value);
                string recipientName = recipient?.Username ?? "Unknown";
                ServerLogger.Log($"[{timestamp}] Message from {senderName} to {recipientName}: {displayText}", LogLevel.Debug);
            }
            else
            {
                // In broadcast mode, logs sender only
                ServerLogger.Log($"[{timestamp}] Broadcast message from {senderName}: {displayText}", LogLevel.Debug);
            }
        }

        /// <summary>
        /// Distributes the sender's public RSA key to all other connected clients.
        /// Constructs a packet with opcode 6, including the sender's UID and public key in Base64 format.
        /// Ensures the sender does not receive their own key to avoid redundant transmission.
        /// Each dispatch is wrapped in a try/catch block to prevent socket exceptions and maintain server stability.
        /// Designed to support dynamic multi-client encryption setup in real-time.
        /// </summary>
        /// <param name="sender">The client who submitted the public key.</param>
        public static void BroadcastPublicKeyToOthers(Client sender)
        {
            foreach (var user in _users)
            {
                // Skips the sender to avoid echoing their own key
                if (user.UID == sender.UID)
                    continue;

                try
                {
                    // Builds the key exchange packet
                    var packet = new PacketBuilder();
                    packet.WriteOpCode(6);                          // Opcode for public key exchange
                    packet.WriteMessage(sender.UID.ToString());     // Sender UID
                    packet.WriteMessage(sender.PublicKeyBase64);    // Public key in Base64

                    // Sends the packet only if the recipient is connected
                    if (user.ClientSocket.Connected)
                    {
                        user.ClientSocket.GetStream().Write(
                            packet.GetPacketBytes(),
                            0,
                            packet.GetPacketBytes().Length
                        );

                        ServerLogger.Log($"[SERVER] Public key from {sender.Username} transmitted to {user.Username}", LogLevel.Debug);
                    }
                }
                catch (Exception ex)
                {
                    // Logs transmission failure for debugging
                    ServerLogger.Log($"[SERVER] Failed to send public key to {user.Username}: {ex.Message}", LogLevel.Error);
                }
            }

            // Logs completion of broadcast
            ServerLogger.Log($"[SERVER] Public key from {sender.Username} transmitted to all other clients.", LogLevel.Debug);
        }

        /// <summary>
        /// Displays the server banner using localized strings.
        /// </summary>

        private static void DisplayBanner()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║          WPF chat server v1.0            ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");
            Console.WriteLine(LocalizationManager.GetString("BannerLine1"));
            Console.WriteLine(LocalizationManager.GetString("BannerLine2") + "\n");
        }

        /// <summary>
        /// Prompts the user to enter a valid TCP port or fallback to default.
        /// </summary>
        /// <returns>Valid port number to use</returns>
        static int GetPortFromUser()
        {
            int defaultPort = 7123;
            int chosenPort = defaultPort;

            Console.Write(LocalizationManager.GetString("PortPrompt"));
            string input = ReadLineWithTimeout(7000); // Wait for user input for 7 seconds

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
                    string confirm = Console.ReadLine()?.Trim().ToLower();

                    if (confirm == "y" || confirm == "o") // "o" for "oui" in French
                    {
                        chosenPort = defaultPort;
                    }
                    else
                    {
                        ServerLogger.Log(LocalizationManager.GetString("Exiting"), LogLevel.Info);
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
        /// <returns>User input or null if timeout</returns>
        static string ReadLineWithTimeout(int timeoutMs)
        {
            string input = null;
            var task = Task.Run(() => input = Console.ReadLine());
            bool completed = task.Wait(timeoutMs);
            return completed ? input : null;
        }

        /// <summary>
        /// Graceful shutdown of the server, notifying all connected clients to disconnect.
        /// Sends a special disconnect command using the system UID to clearly indicate
        /// that the message originates from the server itself.
        /// </summary>
        public static void Shutdown()
        {
            ServerLogger.LogLocalized(LocalizationManager.GetString("ShutdownStart"), LogLevel.Info);

            foreach (var user in _users)
            {
                try
                {
                    var packet = new PacketBuilder();
                    packet.WriteOpCode(5); // Public message opcode
                    packet.WriteMessage(SystemUID.ToString()); // Sender UID (system)
                    packet.WriteMessage("/disconnect");        // Special disconnect command

                    if (user.ClientSocket.Connected)
                    {
                        user.ClientSocket.GetStream().Write(
                            packet.GetPacketBytes(),
                            0,
                            packet.GetPacketBytes().Length
                        );
                    }
                }
                catch (Exception ex)
                {
                    ServerLogger.Log($"[SERVER] Failed to send shutdown to {user.Username}: {ex.Message}", LogLevel.Error);
                }
            }

            ServerLogger.Log(LocalizationManager.GetString("ShutdownComplete"), LogLevel.Info);
        }

        /// <summary>
        /// Starts the TCP listener on the specified port and continuously accepts incoming client connections.
        /// For each connection, reads the handshake packet (opcode 0) containing Username, UID, and RSA public key.
        /// Initializes a Client instance with the received identity and starts its message listener in a separate task.
        /// Adds the client to the global list of users and broadcasts the updated list to all connected clients.
        /// Logs each step for traceability, protocol validation, and debugging.
        /// This method is the entry point for server-side identity registration and real-time routing.
        /// </summary>
        /// <param name="port">The TCP port to listen on.</param>
        public static void StartServerListener(int port)
        {
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();

            ServerLogger.Log($"\n{string.Format(LocalizationManager.GetString("ServerStartedOnPort"), port)}\n", LogLevel.Info);

            while (true)
            {
                try
                {
                    // Accepts a new TCP client
                    TcpClient clientSocket = listener.AcceptTcpClient();
                    ServerLogger.Log($"[SERVER] Incoming connection — Socket: {clientSocket.Client.RemoteEndPoint}", LogLevel.Info);

                    // Initializes a packet reader for the handshake
                    PacketReader reader = new PacketReader(clientSocket.GetStream());

                    // Reads the initial opcode from the handshake packet (0)
                    byte opcode = reader.ReadByte();
                    if (opcode != 0)
                    {
                        ServerLogger.Log($"[SERVER] Unexpected opcode during handshake: {opcode}. Connection aborted.", LogLevel.Error);
                        clientSocket.Close();
                        continue;
                    }

                    // Reads handshake fields in expected order: Username → UID → PublicKey
                    string username = reader.ReadMessage();
                    string uidString = reader.ReadMessage();
                    string publicKeyBase64 = reader.ReadMessage();

                    ServerLogger.Log("[SERVER] Handshake received:", LogLevel.Debug);
                    ServerLogger.Log($"         → Username: {username}", LogLevel.Debug);
                    ServerLogger.Log($"         → UID: {uidString}", LogLevel.Debug);
                    ServerLogger.Log($"         → PublicKeyBase64: {publicKeyBase64.Substring(0, 32)}...", LogLevel.Debug);

                    // Converts UID string to Guid
                    Guid uid = Guid.Parse(uidString);

                    // Creates and initializes the client instance
                    Client client = new Client(clientSocket, username, uid)
                    {
                        PublicKeyBase64 = publicKeyBase64
                    };

                    // Adds the client to the global user list
                    _users.Add(client);

                    // Logs the updated user list and connection details
                    ServerLogger.Log($"[{DateTime.Now}]: Client connected — Username: {username}, UID: {uid}", LogLevel.Info);
                    ServerLogger.Log($"[SERVER] Connected users ({_users.Count}):", LogLevel.Info);
                    foreach (var u in _users)
                    {
                        ServerLogger.Log($"         → {u.Username} ({u.UID})", LogLevel.Debug);
                    }

                    // Starts listening for messages from this client
                    Task.Run(() => client.ListenForMessages());

                    // Broadcasts the updated list of users to all connected clients
                    BroadcastConnection();
                }
                catch (Exception ex)
                {
                    ServerLogger.Log($"[SERVER] Error during client handshake: {ex.Message}", LogLevel.Error);
                }
            }
        }
    }
}
