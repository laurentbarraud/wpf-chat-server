/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 12th, 2025</date>

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
                _listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);

                // Start listening on the selected port
                _listener.Start();
                Console.WriteLine($"\n{LocalizationManager.GetString("ServerStartedOnPort")} {port}.\n");

                // Main loop: accept incoming clients and broadcast their connection
                while (true)
                {
                    var client = new Client(_listener.AcceptTcpClient());
                    _users.Add(client);

                    BroadcastConnection(); // Notify all clients of the new connection
                }
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
        /// Notifies all users of a disconnection and removes the user from the list.
        /// Opcode 10 is used for disconnection notification.
        /// </summary>
        public static void BroadcastDisconnect(string uidDisconnected)
        {
            var disconnectedUser = _users.FirstOrDefault(x => x.UID.ToString() == uidDisconnected);

            if (disconnectedUser != null)
            {
                _users.Remove(disconnectedUser);

                foreach (var user in _users)
                {
                    var broadcastPacket = new PacketBuilder();
                    broadcastPacket.WriteOpCode(10); // Opcode for user disconnect
                    broadcastPacket.WriteMessage(uidDisconnected);
                    user.ClientSocket.Client.Send(broadcastPacket.GetPacketBytes());
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
        /// Sends a packet to each connected user to notify them of all current users.
        /// Opcode 1 indicates a user connection broadcast.
        /// </summary>
        public static void BroadcastConnection()
        {
            foreach (var user in _users)
            {
                foreach (var usr in _users)
                {
                    var broadcastPacket = new PacketBuilder();
                    broadcastPacket.WriteOpCode(1); // Opcode for user connection
                    broadcastPacket.WriteMessage(usr.Username);
                    broadcastPacket.WriteMessage(usr.UID.ToString());
                    user.ClientSocket.Client.Send(broadcastPacket.GetPacketBytes());
                }
            }
        }

        /// <summary>
        /// Broadcasts the public key of a newly connected client to all other clients.
        /// Opcode 6 is used for public key exchange.
        /// </summary>
        /// <param name="sender">The client who submitted their public key.</param>
        public static void BroadcastPublicKeyToOthers(Client sender)
        {
            foreach (var receiver in _users)
            {
                // Skip the sender — no need to send their own key back
                if (receiver == sender)
                    continue;

                var keyPacket = new PacketBuilder();
                keyPacket.WriteOpCode(6); // Opcode for public key exchange
                keyPacket.WriteMessage(sender.UID.ToString()); // UID of the sender
                keyPacket.WriteMessage(sender.PublicKeyBase64); // Public key in Base64

                receiver.ClientSocket.Client.Send(keyPacket.GetPacketBytes());
            }

            // Log the broadcast event
            Console.WriteLine($"[{DateTime.Now}]: Public key received from: {sender.Username} — transmitted to other clients.");
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
    }
}
