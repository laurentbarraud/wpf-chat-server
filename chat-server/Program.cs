/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 9th, 2025</date>

using chat_server.Net.IO;
using ChatServer.Helpers;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;

namespace chat_server
{
    public class Program
    {
        static List<Client> _users; // List to store all connected clients
        static TcpListener _listener; // TCP listener for incoming connections

        // Global language code used throughout the app
        public static string AppLanguage = "en";

        public static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            // Handle Ctrl+C to gracefully shut down the server
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Shutdown();
                Environment.Exit(0);
            };

            // Detect system culture (e.g. "fr", "en", "de")
            string systemCulture = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;

            // Apply "fr" if system language is French, otherwise default to "en"
            AppLanguage = systemCulture == "fr" ? "fr" : "en";

            // Initialize localization manager with selected language
            LocalizationManager.Initialize(AppLanguage);

            // Display localized banner
            DisplayBanner();

            // Ask user for TCP port or use default
            int port = GetPortFromUser(); 

            try
            {
                _users = new List<Client>();
                _listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
                
                // Start listening on the selected port
                _listener.Start(); 
                Console.WriteLine($"\n Server started on port {port}.\n");

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
                // If server fails to start, display error and exit
                Console.WriteLine($"\n Failed to start server on port {port}: {ex.Message}");
                Console.WriteLine("Exiting...");
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Displays the appropriate server banner based on current language.
        /// </summary>
        private static void DisplayBanner()
        {
            if (Program.AppLanguage == "fr")
            {
                DisplayBanner_Fr();
            }
            else
            {
                DisplayBanner_En();
            }
        }

        /// <summary>
        /// Displays the server banner in English.
        /// </summary>
        private static void DisplayBanner_En()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║         WPF Chat Server v1.0             ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");
            Console.WriteLine("Press Ctrl+C to stop the server.");
            Console.WriteLine("Change the TCP port used for listening or wait 8 seconds.\n");
        }

        /// <summary>
        /// Displays the server banner in French.
        /// </summary>
        private static void DisplayBanner_Fr()
        {
            Console.WriteLine("╔══════════════════════════════════════════╗");
            Console.WriteLine("║         Serveur de Chat WPF v1.0         ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");
            Console.WriteLine("Appuyez sur Ctrl+C pour arrêter le serveur.");
            Console.WriteLine("Changez le port TCP utilisé pour l’écoute ou attendez 8 secondes.\n");
        }


        /// <summary>
        /// Prompts the user to enter a valid TCP port or fallback to default.
        /// </summary>
        /// <returns>Valid port number to use</returns>
        static int GetPortFromUser()
        {
            int defaultPort = 7123;
            int chosenPort = defaultPort;

            Console.Write("Enter a port number between 1000 and 65535 [default: 7123]: ");
            string input = ReadLineWithTimeout(8000); // Wait for user input for 8 seconds

            if (!string.IsNullOrWhiteSpace(input))
            {
                // Validate port number
                if (int.TryParse(input, out int port) && port >= 1000 && port <= 65535)
                {
                    chosenPort = port;
                }
                else
                {
                    // Ask user if they want to use default port
                    Console.Write("Invalid port, would you like to use default port (7123)? (y/n): ");
                    string confirm = Console.ReadLine()?.Trim().ToLower();

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
        /// <returns>User input or null if timeout</returns>
        static string ReadLineWithTimeout(int timeoutMs)
        {
            string input = null;
            var task = Task.Run(() => input = Console.ReadLine());
            bool completed = task.Wait(timeoutMs);
            return completed ? input : null;
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
        /// Sends a message to all connected users.
        /// Opcode 5 is used for general messages.
        /// </summary>
        public static void BroadcastMessage(string messageToBroadcast)
        {
            foreach (var user in _users)
            {
                var msgPacket = new PacketBuilder();
                msgPacket.WriteOpCode(5); // Opcode for chat message
                msgPacket.WriteMessage(messageToBroadcast);
                user.ClientSocket.Client.Send(msgPacket.GetPacketBytes());
            }
        }

        /// <summary>
        /// Notifies all users of a disconnection and removes the user from the list.
        /// Opcode 10 is used for disconnection notification.
        /// </summary>
        public static void BroadcastDisconnect(string uidDisconnected)
        {
            var disconnectedUser = _users.Where(x => x.UID.ToString() == uidDisconnected).FirstOrDefault();

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
        /// Gracefully shuts down the server and notifies clients to disconnect.
        /// </summary>
        public static void Shutdown()
        {
            Console.WriteLine("Shutting down server...");
            BroadcastMessage("/disconnect"); // Special command for client to disconnect
            Console.WriteLine("Server shutdown complete.");
        }
    }
}
