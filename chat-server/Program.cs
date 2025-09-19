/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 19th, 2025</date>

using chat_server.Net.IO;
using chat_server.Helpers;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace chat_server
{
    /// <summary>
    /// Entry point for the WPF Chat Server application.
    /// Handles client connections, message broadcasting, and localization.
    /// </summary>
    public class Program
    {
        static List<Client> _users; // Stores all connected clients
        static TcpListener _listener; // TCP listener for incoming connections

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

            // Detect system language and initialize localization
            string systemCulture = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            AppLanguage = systemCulture == "fr" ? "fr" : "en";
            LocalizationManager.Initialize(AppLanguage);

            // Display localized banner
            DisplayBanner();

            // Prompt user for TCP port or use default
            int portToListenTo = GetPortFromUser();

            try
            {
                _users = new List<Client>();

                // Start listening for incoming clients
                StartServerListener(portToListenTo);

            }
            catch (Exception ex)
            {
                // Display error if server fails to start
                Console.WriteLine($"\n{LocalizationManager.GetString("ServerStartFailed")} {portToListenTo}: {ex.Message}");
                Console.WriteLine(LocalizationManager.GetString("Exiting"));
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Sends the full roster of connected users to each client.
        /// Uses opcode 1 to broadcast user presence.
        /// Iterates through all users and sends each entry to every other client.
        /// Logs each transmission for traceability.
        /// </summary>
        public static void BroadcastConnection()
        {
            foreach (var receiver in _users)
            {
                foreach (var usr in _users)
                {
                    var broadcastPacket = new PacketBuilder();
                    broadcastPacket.WriteOpCode(1); // Opcode for user connection
                    broadcastPacket.WriteMessage(usr.Username);
                    broadcastPacket.WriteMessage(usr.UID.ToString());
                    receiver.ClientSocket.Client.Send(broadcastPacket.GetPacketBytes());

                    Console.WriteLine($"[SERVER] Sent roster entry — {usr.Username} ({usr.UID}) to {receiver.Username}");
                }
            }

            Console.WriteLine("[SERVER] Full roster broadcast completed.");
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
            var disconnectedUser = _users.FirstOrDefault(x => x.UID.ToString() == uidDisconnected);

            if (disconnectedUser != null)
            {
                _users.Remove(disconnectedUser);
                Console.WriteLine($"[SERVER] User removed from roster — {disconnectedUser.Username} ({uidDisconnected})");

                foreach (var user in _users)
                {
                    try
                    {
                        var packet = new PacketBuilder();
                        packet.WriteOpCode(10);
                        packet.WriteMessage(uidDisconnected);

                        if (user.ClientSocket.Connected)
                        {
                            user.ClientSocket.GetStream().Write(
                                packet.GetPacketBytes(),
                                0,
                                packet.GetPacketBytes().Length
                            );

                            Console.WriteLine($"[SERVER] Sent disconnect notification to {user.Username} for UID {uidDisconnected}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[SERVER] Failed to notify {user.Username} of disconnect: {ex.Message}");
                    }
                }
            }
        }

        /// <summary>
        /// Broadcasts a chat message to all connected clients except the sender.
        /// Includes the message content and sender UID.
        /// Logs the message with timestamp and localization support.
        /// If the message is encrypted, displays only the [ENC] tag.
        /// </summary>
        /// <param name="message">The message content to broadcast.</param>
        /// <param name="senderUid">The UID of the sender.</param>
        public static void BroadcastMessage(string message, Guid senderUid)
        {
            var sender = _users.FirstOrDefault(u => u.UID == senderUid);
            string displayName = sender?.Username ?? "unknown";

            // Formats the message for logging
            string displayMessage = message.StartsWith("[ENC]") ? "[ENC]" : message;
            string timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");
            string localizedLog = string.Format(LocalizationManager.GetString("MessageReceived"), displayName, displayMessage);

            Console.WriteLine($"[{timestamp}]: {localizedLog}");

            foreach (var user in _users)
            {
                if (user.UID == senderUid)
                    continue;

                try
                {
                    var packet = new PacketBuilder();
                    packet.WriteOpCode(5); // Opcode for public chat message
                    packet.WriteMessage(message);       // Full message (encrypted or plain)
                    packet.WriteMessage(senderUid.ToString()); // Sender UID

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
                    Console.WriteLine($"[SERVER] Failed to relay message to {user.Username}: {ex.Message}");
                }
            }
        }


        /// <summary>
        /// Broadcasts the sender's public RSA key to all other connected clients.
        /// Builds a packet with opcode 6, including the sender's UID and public key in Base64 format.
        /// Ensures that the sender does not receive their own key.
        /// Wraps each transmission in a try/catch block to prevent socket exceptions.
        /// Logs each dispatch for traceability.
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
                    var packet = new PacketBuilder();
                    packet.WriteOpCode(6); // Opcode for public key exchange
                    packet.WriteMessage(sender.UID.ToString());       // Sender UID
                    packet.WriteMessage(sender.PublicKeyBase64);      // Public key in Base64

                    if (user.ClientSocket.Connected)
                    {
                        user.ClientSocket.GetStream().Write(
                            packet.GetPacketBytes(),
                            0,
                            packet.GetPacketBytes().Length
                        );

                        Console.WriteLine($"[SERVER] Public key from {sender.Username} transmitted to {user.Username}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SERVER] Failed to send public key to {user.Username}: {ex.Message}");
                }
            }

            Console.WriteLine($"[SERVER] Public key from {sender.Username} transmitted to all other clients.");
        }

        /// <summary>
        /// Displays the server banner using localized strings.
        /// </summary>
        private static void DisplayBanner()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║          WPF Chat Server v1.0            ║");
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
                        Console.WriteLine(LocalizationManager.GetString("Exiting"));
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
            Console.WriteLine(LocalizationManager.GetString("ShutdownStart"));
            BroadcastMessage("/disconnect", SystemUID); // Special command for client to disconnect
            Console.WriteLine(LocalizationManager.GetString("ShutdownComplete"));
        }

        /// <summary>
        /// Starts the TCP listener on the specified port and accepts incoming client connections.
        /// Reads the handshake packet (opcode 0 + username) before creating the Client instance.
        /// Initializes the client and starts its message listener in a separate task.
        /// Logs the localized startup message and each connection for traceability.
        /// </summary>
        /// <param name="port">The TCP port to listen on.</param>
        public static void StartServerListener(int port)
        {
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();

            Console.WriteLine($"\n{string.Format(LocalizationManager.GetString("ServerStartedOnPort"), port)}\n");

            while (true)
            {
                try
                {
                    // Accepts a new TCP client
                    TcpClient clientSocket = listener.AcceptTcpClient();

                    // Initializes a packet reader for the handshake
                    PacketReader reader = new PacketReader(clientSocket.GetStream());

                    // Reads the initial opcode from the handshake packet
                    byte opcode = reader.ReadByte();
                    if (opcode != 0)
                    {
                        Console.WriteLine($"[SERVER] Unexpected opcode during handshake: {opcode}. Connection aborted.");
                        clientSocket.Close();
                        continue;
                    }

                    // Reads the username from the handshake packet
                    string username = reader.ReadMessage();

                    // Creates and initializes the client instance
                    Client client = new Client(clientSocket, username);

                    // Adds the client to the global user list
                    _users.Add(client);
                    Console.WriteLine($"[{DateTime.Now}]: Client connected with username: {username}");
                    Console.WriteLine($"[SERVER] New client accepted — Socket: {clientSocket.Client.RemoteEndPoint}");

                    // Starts listening for messages from this client
                    Task.Run(() => client.ListenForMessages());

                    // Broadcasts the updated roster to all connected clients
                    BroadcastConnection();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SERVER] Error during client handshake: {ex.Message}");
                }
            }
        }
    }
}
