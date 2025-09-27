/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 27th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

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

        public static readonly List<Client> Users = new();
        public static string AppLanguage = "en";
        public static readonly Guid SystemUID =
            Guid.Parse("00000000-0000-0000-0000-000000000001");

        private static void Log(ServerLogLevel level, string message)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            Console.WriteLine($"[{timestamp}][{level}] {message}");
        }

        private static void LogL(ServerLogLevel level, string resourceKey)
        {
            string text = LocalizationManager.GetString(resourceKey);
            Log(level, text);
        }

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
                e.Cancel = true;
                Shutdown();
                Environment.Exit(0);
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
            }
            catch (Exception ex)
            {
                // Logs failure to start the listener on the chosen port.
                Log(ServerLogLevel.Error,
                    $"{LocalizationManager.GetString("ServerStartFailed")} {portToListenTo}: {ex.Message}");

                // Logs that the application is exiting and then terminates.
                Log(ServerLogLevel.Info, LocalizationManager.GetString("Exiting"));
                Environment.Exit(1);
            }
        }

        /// <summary>Broadcasts full user list (opcode 1) to every client.</summary>
        public static void BroadcastConnection()
        {
            foreach (var receiver in Users)
            {
                foreach (var usr in Users)
                {
                    var broadcastConnectionPacket = new PacketBuilder();
                    broadcastConnectionPacket.WriteOpCode((byte)ServerPacketOpCode.ConnectionBroadcast);
                    broadcastConnectionPacket.WriteMessage(usr.UID.ToString());
                    broadcastConnectionPacket.WriteMessage(usr.Username);
                    broadcastConnectionPacket.WriteMessage(usr.PublicKeyBase64);

                    receiver.ClientSocket.Client
                        .Send(broadcastConnectionPacket.GetPacketBytes());

                    Log(ServerLogLevel.Debug, "[SERVER] Broadcasting user list entry");
                }
            }
            Log(ServerLogLevel.Debug, "[SERVER] Completed user list broadcast");
        }

        /// <summary>Notifies clients of a disconnection (opcode 10) and logs each send.</summary>
        public static void BroadcastDisconnect(string uid)
        {
            var disc = Users.FirstOrDefault(u => u.UID.ToString() == uid);
            if (disc == null) return;

            foreach (var user in Users)
            {
                try
                {
                    var broadcastDisconnectPacket = new PacketBuilder();
                    broadcastDisconnectPacket.WriteOpCode((byte)ServerPacketOpCode.DisconnectNotify);
                    broadcastDisconnectPacket.WriteMessage(uid);

                    if (user.ClientSocket.Connected)
                    {
                        user.ClientSocket.GetStream()
                            .Write(broadcastDisconnectPacket.GetPacketBytes(), 0,
                                   broadcastDisconnectPacket.GetPacketBytes().Length);
                    }
                    Log(ServerLogLevel.Debug,
                        $"[SERVER] Notified {user.Username} of disconnection");
                }
                catch (Exception ex)
                {
                    Log(ServerLogLevel.Error,
                        $"[SERVER] Disconnect notification failed: {ex.Message}");
                }
            }
        }

        /// <summary>Routes a plain message packet (opcode 5) to all clients.</summary>
        public static void BroadcastMessage(string content, Guid senderUid, Guid? recipientUid = null)
        {
            var sender = Users.FirstOrDefault(u => u.UID == senderUid);
            string sName = sender?.Username ?? "Unknown";
            string disp = content.StartsWith("[ENC]") ? "[Encrypted]" : content;
            string time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            if (recipientUid.HasValue)
            {
                var r = Users.FirstOrDefault(u => u.UID == recipientUid);
                Log(ServerLogLevel.Debug,
                    $"[{time}] Message from {sName} to {r?.Username ?? "Unknown"}: {disp}");
            }
            else
            {
                Log(ServerLogLevel.Debug,
                    $"[{time}] Broadcast message from {sName}: {disp}");
            }

            foreach (var user in Users)
            {
                if (recipientUid.HasValue && user.UID != recipientUid) continue;

                try
                {
                    var broadcastPlainMessagePacket = new PacketBuilder();
                    broadcastPlainMessagePacket.WriteOpCode((byte)ServerPacketOpCode.PlainMessage);
                    broadcastPlainMessagePacket.WriteMessage(senderUid.ToString());
                    broadcastPlainMessagePacket.WriteMessage(recipientUid?.ToString() ?? "");
                    broadcastPlainMessagePacket.WriteMessage(content);

                    if (user.ClientSocket.Connected)
                        user.ClientSocket.GetStream()
                            .Write(broadcastPlainMessagePacket.GetPacketBytes(), 0, broadcastPlainMessagePacket.GetPacketBytes().Length);
                }
                catch (Exception ex)
                {
                    Log(ServerLogLevel.Debug,
                        $"[SERVER] Send failed to {user.Username}: {ex.Message}");
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
                    broadcastPublicKeyPacket.WriteMessage(sender.UID.ToString());
                    broadcastPublicKeyPacket.WriteMessage(sender.PublicKeyBase64);
                    if (user.ClientSocket.Connected)
                        user.ClientSocket.GetStream()
                            .Write(broadcastPublicKeyPacket.GetPacketBytes(), 0, broadcastPublicKeyPacket.GetPacketBytes().Length);

                    Log(ServerLogLevel.Debug,
                        $"[SERVER] Transmitted public key from {sender.Username} to {user.Username}");
                }
                catch (Exception ex)
                {
                    Log(ServerLogLevel.Error,
                        $"[SERVER] Public key transmission failed: {ex.Message}");
                }
            }
            Log(ServerLogLevel.Debug,
                "[SERVER] Completed public key broadcast");
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


        /// <summary>Reads a console line with a timeout.</summary>
        private static string ReadLineWithTimeout(int timeoutMs)
        {
            string? result = null;
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
            LogL(ServerLogLevel.Info, "ShutdownStart");

            foreach (var user in Users)
            {
                try
                {
                    var _packetBuilder = new PacketBuilder();
                    _packetBuilder.WriteOpCode(5);
                    _packetBuilder.WriteMessage(SystemUID.ToString());
                    _packetBuilder.WriteMessage("/disconnect");

                    if (user.ClientSocket.Connected)
                        user.ClientSocket.GetStream()
                            .Write(_packetBuilder.GetPacketBytes(), 0, _packetBuilder.GetPacketBytes().Length);
                }
                catch (Exception ex)
                {
                    Log(ServerLogLevel.Error,
                        $"[SERVER] Shutdown notification failed: {ex.Message}");
                }
            }
            LogL(ServerLogLevel.Info, "ShutdownComplete");
        }

        /// <summary>
        /// Starts a TCP listener on the specified port, performs client handshakes,
        /// validates RSA keys, registers new clients, and broadcasts the roster.
        /// Logs each major step and handles unexpected conditions.
        /// </summary>
        public static void StartServerListener(int port)
        {
            // Creates and starts the TCP listener on all network interfaces
            _listener = new TcpListener(IPAddress.Any, port);
            _listener.Start();

            Console.WriteLine("\n");

            // Logs that the server has successfully started on the specified port
            Log(ServerLogLevel.Info, string.Format(LocalizationManager.GetString("ServerStartedOnPort"), port));

            while (true)
            {
                try
                {
                    // Accepts an incoming TCP connection
                    TcpClient tcpClient = _listener.AcceptTcpClient();
                    string endpoint = tcpClient.Client.RemoteEndPoint?.ToString() ?? "Unknown endpoint";
                    Log(ServerLogLevel.Info, $"Incoming connection from {endpoint}");

                    NetworkStream stream = tcpClient.GetStream();

                    // Reads the handshake opcode byte
                    int opcode = stream.ReadByte();
                    if ((ServerPacketOpCode)opcode != ServerPacketOpCode.Handshake)
                    {
                        Log(ServerLogLevel.Error, $"Unexpected handshake opcode: {opcode}. Disconnecting.");
                        tcpClient.Close();
                        continue;
                    }

                    // Parses the Username, UID string, and Base64 public key
                    var _packetReader = new PacketReader(stream);
                    string username = _packetReader.ReadMessage();
                    string uidString = _packetReader.ReadMessage();
                    string publicKeyBase64 = _packetReader.ReadMessage();

                    Log(ServerLogLevel.Debug, "[SERVER] Handshake received:");
                    Log(ServerLogLevel.Debug, $"  → Username: {username}");
                    Log(ServerLogLevel.Debug, $"  → UID: {uidString}");
                    Log(ServerLogLevel.Debug, $"  → Key fragment: {publicKeyBase64.Substring(0, 32)}…");

                    // Parses and validates the client's GUID
                    Guid uid = Guid.Parse(uidString);

                    // Imports the RSA public key in PKCS#1 DER format
                    byte[] derBytes = Convert.FromBase64String(publicKeyBase64);
                    using var rsa = RSA.Create();
                    rsa.ImportRSAPublicKey(derBytes, out _);

                    // Instantiates and registers the client
                    var client = new Client(tcpClient, username, uid)
                    {
                        PublicKeyDer = derBytes,
                        PublicKeyBase64 = publicKeyBase64
                    };
                    Users.Add(client);

                    Log(ServerLogLevel.Info, $"Client connected: {username} ({uid})");
                    Log(ServerLogLevel.Info, $"[SERVER] User count: {Users.Count}");
                    foreach (var u in Users)
                        Log(ServerLogLevel.Debug, $"  → {u.Username} ({u.UID})");

                    // Spawns the message listener and updates the roster
                    Task.Run(() => client.ListenForMessages());
                    BroadcastConnection();
                }
                catch (Exception ex)
                {
                    // Logs any exception during the handshake process
                    Log(ServerLogLevel.Error, $"[SERVER] Handshake error: {ex.Message}");
                }
            }
        }
    }
}
