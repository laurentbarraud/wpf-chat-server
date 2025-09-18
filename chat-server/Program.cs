/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 18th, 2025</date>

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
            int port = GetPortFromUser();

            try
            {
                _users = new List<Client>();
                Console.WriteLine($"\n{LocalizationManager.GetString("ServerStartedOnPort")} {port}.\n");

                // Start listening for incoming clients
                StartServerListener();

            }
            catch (Exception ex)
            {
                // Display error if server fails to start
                Console.WriteLine($"\n{LocalizationManager.GetString("ServerStartFailed")} {port}: {ex.Message}");
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
        /// Logs each notification for traceability.
        /// </summary>
        /// <param name="uidDisconnected">The UID of the user who disconnected.</param>
        public static void BroadcastDisconnect(string uidDisconnected)
        {
            // Locates the disconnected user in the list
            var disconnectedUser = _users.FirstOrDefault(x => x.UID.ToString() == uidDisconnected);

            if (disconnectedUser != null)
            {
                // Removes the user from the active list
                _users.Remove(disconnectedUser);
                Console.WriteLine($"[SERVER] User removed from roster — {disconnectedUser.Username} ({uidDisconnected})");

                // Notifies all remaining users of the disconnection
                foreach (var user in _users)
                {
                    var broadcastPacket = new PacketBuilder();
                    broadcastPacket.WriteOpCode(10); // Opcode for user disconnect
                    broadcastPacket.WriteMessage(uidDisconnected);
                    user.ClientSocket.Client.Send(broadcastPacket.GetPacketBytes());

                    Console.WriteLine($"[SERVER] Sent disconnect notification to {user.Username} for UID {uidDisconnected}");
                }
            }
        }

        /// <summary>
        /// Sends a message to all connected users.
        /// Opcode 5 is used for general messages.
        /// Each packet includes the message content and the sender's UID
        /// so that clients can identify the sender and decrypt if needed.
        /// </summary>
        public static void BroadcastMessage(string messageToBroadcast, Guid senderUID)
        {
            foreach (var user in _users)
            {
                var msgPacket = new PacketBuilder();
                msgPacket.WriteOpCode(5); // Opcode for chat message

                // Write the message content (may be encrypted or plain text)
                msgPacket.WriteMessage(messageToBroadcast);

                // Write the sender's UID so clients can identify the sender
                msgPacket.WriteMessage(senderUID.ToString());

                // Send the packet to the connected client
                user.ClientSocket.Client.Send(msgPacket.GetPacketBytes());
            }
        }

        /// <summary>
        /// Broadcasts the public RSA key of a newly connected client to all other clients.
        /// Uses opcode 6 to signal public key exchange.
        /// Skips the sender to avoid redundant transmission.
        /// Logs each dispatch for traceability and confirms successful propagation.
        /// </summary>
        /// <param name="sender">The client who submitted their public key.</param>
        public static void BroadcastPublicKeyToOthers(Client sender)
        {
            foreach (var receiver in _users)
            {
                // Skip the sender — no need to send their own key back
                if (receiver == sender)
                    continue;

                // Builds the key exchange packet
                var keyPacket = new PacketBuilder();
                keyPacket.WriteOpCode(6); // Opcode for public key exchange
                keyPacket.WriteMessage(sender.UID.ToString()); // UID of the sender
                keyPacket.WriteMessage(sender.PublicKeyBase64); // Public key in Base64

                // Sends the packet to the receiver
                receiver.ClientSocket.Client.Send(keyPacket.GetPacketBytes());

                // Logs the dispatch
                Console.WriteLine($"[{DateTime.Now}]: Forwarded public key of {sender.Username} to {receiver.Username}");
            }

            // Logs the broadcast summary
            Console.WriteLine($"[{DateTime.Now}]: Public key from {sender.Username} transmitted to all other clients.");
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
        /// Starts the TCP listener and accepts incoming client connections.
        /// For each accepted client, creates a Client instance and starts its message listener in a separate task.
        /// Logs each connection for traceability.
        /// </summary>
        public static void StartServerListener()
        {
            // Initializes the TCP listener on port 7123
            TcpListener listener = new TcpListener(IPAddress.Any, 7123);
            listener.Start();

            Console.WriteLine("[SERVER] Listener started — waiting for incoming connections...");

            while (true)
            {
                // Accepts a new TCP client
                TcpClient clientSocket = listener.AcceptTcpClient();

                // Creates a new Client instance to handle this connection
                Client client = new Client(clientSocket);

                // Adds the client to the global user list
                _users.Add(client);
                Console.WriteLine($"[SERVER] New client accepted — Socket: {clientSocket.Client.RemoteEndPoint}");

                // Starts listening for messages from this client in a separate task
                Task.Run(() => client.ListenForMessages());
            }
        }

    }
}
