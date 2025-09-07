/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.9</version>
/// <date>September 7th, 2025</date>

using chat_server.Net.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace chat_server
{
    public class Program
    {
        static List<Client> _users; // List to store all connected clients
        static TcpListener _listener; // TCP listener for incoming connections

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

            DisplayBanner(); // Show server title and instructions

            int port = GetPortFromUser(); // Ask user for TCP port or use default

            try
            {
                _users = new List<Client>();
                _listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
                _listener.Start(); // Start listening on the selected port
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
        /// Displays the server banner and usage instructions.
        /// </summary>
        static void DisplayBanner()
        {
            Console.WriteLine("************************************");
            Console.WriteLine("      WPF Chat Server v0.9");
            Console.WriteLine("                                    ");
            Console.WriteLine("************************************\n");
            Console.WriteLine("Press Ctrl + C to quit.\n");
            Console.WriteLine("Change the TCP port used for listening or wait 5 seconds\n");
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
            string input = ReadLineWithTimeout(5000); // Wait for user input for 5 seconds

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
