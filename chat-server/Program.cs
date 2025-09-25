/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

using chat_server.Helpers;
using chat_server.Net.IO;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace chat_server
{
    /// <summary>
    /// Entry point and coordinator for the server-side chat system.
    /// Manages client connections, handshakes, and broadcasts for presence,
    /// messages, public keys, and disconnections using a local console logger.
    /// </summary>
    public class Program
    {
        // Fields
        private static TcpListener _listener;
        public static readonly List<Client> Users = new();
        public static string AppLanguage = "en";
        public static readonly Guid SystemUID =
            Guid.Parse("00000000-0000-0000-0000-000000000001");

        // Local logger
        private enum LogLevelLocal { Debug, Info, Warn, Error }

        private static void Log(LogLevelLocal level, string message)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            Console.WriteLine($"[{timestamp}][{level}] {message}");
        }

        private static void LogL(LogLevelLocal level, string resourceKey)
        {
            string text = LocalizationManager.GetString(resourceKey);
            Log(level, text);
        }

        // Main
        public static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                Shutdown();
                Environment.Exit(0);
            };

            string culture = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            AppLanguage = culture == "fr" ? "fr" : "en";
            LocalizationManager.Initialize(AppLanguage);

            #if DEBUG
            ServerLogHelper.IsDebugEnabled = true;
            #else
            ServerLogHelper.IsDebugEnabled = args.Contains("--debug");
            #endif

            DisplayBanner();
            int port = GetPortFromUser();

            try { StartServerListener(port); }
            catch (Exception ex)
            {
                Log(LogLevelLocal.Error,
                    $"{LocalizationManager.GetString("ServerStartFailed")} {port}: {ex.Message}");
                Log(LogLevelLocal.Info, LocalizationManager.GetString("Exiting"));
                Environment.Exit(1);
            }
        }

        // BroadcastConnection
        /// <summary>Broadcasts full user list (opcode 1) to every client.</summary>
        public static void BroadcastConnection()
        {
            foreach (var receiver in Users)
            {
                foreach (var usr in Users)
                {
                    var packet = new PacketBuilder();
                    packet.WriteOpCode(1);
                    packet.WriteMessage(usr.UID.ToString());
                    packet.WriteMessage(usr.Username);
                    packet.WriteMessage(usr.PublicKeyBase64);

                    receiver.ClientSocket.Client
                        .Send(packet.GetPacketBytes());

                    Log(LogLevelLocal.Debug, "[SERVER] Broadcasting user list entry");
                }
            }
            Log(LogLevelLocal.Debug, "[SERVER] Completed user list broadcast");
        }

        // BroadcastDisconnect
        /// <summary>Notifies clients of a disconnection (opcode 10) and logs each send.</summary>
        public static void BroadcastDisconnect(string uid)
        {
            var disc = Users.FirstOrDefault(u => u.UID.ToString() == uid);
            if (disc == null) return;

            foreach (var user in Users)
            {
                try
                {
                    var packet = new PacketBuilder();
                    packet.WriteOpCode(10);
                    packet.WriteMessage(uid);

                    if (user.ClientSocket.Connected)
                    {
                        user.ClientSocket.GetStream()
                            .Write(packet.GetPacketBytes(), 0,
                                   packet.GetPacketBytes().Length);
                    }
                    Log(LogLevelLocal.Debug,
                        $"[SERVER] Notified {user.Username} of disconnection");
                }
                catch (Exception ex)
                {
                    Log(LogLevelLocal.Error,
                        $"[SERVER] Disconnect notification failed: {ex.Message}");
                }
            }
        }

        // BroadcastMessage
        /// <summary>Routes a chat packet (opcode 5) to one or all clients.</summary>
        public static void BroadcastMessage(string content, Guid senderUid, Guid? recipientUid = null)
        {
            var sender = Users.FirstOrDefault(u => u.UID == senderUid);
            string sName = sender?.Username ?? "Unknown";
            string disp = content.StartsWith("[ENC]") ? "[Encrypted]" : content;
            string time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            if (recipientUid.HasValue)
            {
                var r = Users.FirstOrDefault(u => u.UID == recipientUid);
                Log(LogLevelLocal.Debug,
                    $"[{time}] Message from {sName} to {r?.Username ?? "Unknown"}: {disp}");
            }
            else
            {
                Log(LogLevelLocal.Debug,
                    $"[{time}] Broadcast message from {sName}: {disp}");
            }

            foreach (var user in Users)
            {
                if (recipientUid.HasValue && user.UID != recipientUid) continue;

                try
                {
                    var b = new PacketBuilder();
                    b.WriteOpCode(5);
                    b.WriteMessage(senderUid.ToString());
                    b.WriteMessage(recipientUid?.ToString() ?? "");
                    b.WriteMessage(content);

                    if (user.ClientSocket.Connected)
                        user.ClientSocket.GetStream()
                            .Write(b.GetPacketBytes(), 0, b.GetPacketBytes().Length);
                }
                catch (Exception ex)
                {
                    Log(LogLevelLocal.Debug,
                        $"[SERVER] Send failed to {user.Username}: {ex.Message}");
                }
            }
        }

        // BroadcastPublicKeyToOthers
        /// <summary>Distributes sender's public key (opcode 6) to other clients.</summary>
        public static void BroadcastPublicKeyToOthers(Client sender)
        {
            foreach (var user in Users)
            {
                if (user.UID == sender.UID) continue;
                try
                {
                    var p = new PacketBuilder();
                    p.WriteOpCode(6);
                    p.WriteMessage(sender.UID.ToString());
                    p.WriteMessage(sender.PublicKeyBase64);
                    if (user.ClientSocket.Connected)
                        user.ClientSocket.GetStream()
                            .Write(p.GetPacketBytes(), 0, p.GetPacketBytes().Length);

                    Log(LogLevelLocal.Debug,
                        $"[SERVER] Transmitted public key from {sender.Username} to {user.Username}");
                }
                catch (Exception ex)
                {
                    Log(LogLevelLocal.Error,
                        $"[SERVER] Public key transmission failed: {ex.Message}");
                }
            }
            Log(LogLevelLocal.Debug,
                "[SERVER] Completed public key broadcast");
        }

        // DisplayBanner
        /// <summary>Displays the localized startup banner.</summary>
        private static void DisplayBanner()
        {
            Console.WriteLine("╔═══════════════════════════════════╗");
            Console.WriteLine("║          WPF Chat Server          ║");
            Console.WriteLine("╚═══════════════════════════════════╝");
            Console.WriteLine(LocalizationManager.GetString("BannerLine1"));
            Console.WriteLine(LocalizationManager.GetString("BannerLine2"));
        }

        // GetPortFromUser
        /// <summary>Prompts for a valid TCP port with timeout and fallback.</summary>
        private static int GetPortFromUser()
        {
            const int defaultPort = 7123;
            Console.Write(LocalizationManager.GetString("PortPrompt"));
            string input = ReadLineWithTimeout(7000);

            if (int.TryParse(input, out int port) && port >= 1000 && port <= 65535)
                return port;

            Console.Write(LocalizationManager.GetString("InvalidPortPrompt"));
            string confirm = Console.ReadLine()?.Trim().ToLower();
            if (confirm == "y" || confirm == "o")
                return defaultPort;

            Log(LogLevelLocal.Info, LocalizationManager.GetString("Exiting"));
            Environment.Exit(0);
            return defaultPort;
        }

        // ReadLineWithTimeout
        /// <summary>Reads a console line with a timeout.</summary>
        private static string ReadLineWithTimeout(int timeoutMs)
        {
            string result = null;
            Task.Run(() => result = Console.ReadLine()).Wait(timeoutMs);
            return result ?? string.Empty;
        }

        // Shutdown
        /// <summary>Sends "/disconnect" to all clients then exits.</summary>
        public static void Shutdown()
        {
            LogL(LogLevelLocal.Info, "ShutdownStart");

            foreach (var user in Users)
            {
                try
                {
                    var p = new PacketBuilder();
                    p.WriteOpCode(5);
                    p.WriteMessage(SystemUID.ToString());
                    p.WriteMessage("/disconnect");

                    if (user.ClientSocket.Connected)
                        user.ClientSocket.GetStream()
                            .Write(p.GetPacketBytes(), 0, p.GetPacketBytes().Length);
                }
                catch (Exception ex)
                {
                    Log(LogLevelLocal.Error,
                        $"[SERVER] Shutdown notification failed: {ex.Message}");
                }
            }
            LogL(LogLevelLocal.Info, "ShutdownComplete");
        }

        // StartServerListener
        /// <summary>
        /// Starts a TCP listener on the specified port, performs handshakes,
        /// validates/imports client RSA keys, registers clients, and
        /// broadcasts the updated roster. Logs each major step.
        /// </summary>
        public static void StartServerListener(int port)
        {
            _listener = new TcpListener(IPAddress.Any, port);
            _listener.Start();
            Log(LogLevelLocal.Info,
                $"{LocalizationManager.GetString("ServerStartedOnPort")} {port}");

            while (true)
            {
                try
                {
                    TcpClient tcpClient = _listener.AcceptTcpClient();
                    string remoteEndpoint = tcpClient.Client.RemoteEndPoint?
                        .ToString() ?? "Unknown endpoint";
                    Log(LogLevelLocal.Info,
                        $"Incoming connection from {remoteEndpoint}");

                    var reader = new PacketReader(tcpClient.GetStream());
                    byte opcode = reader.ReadByte();
                    if (opcode != 0)
                    {
                        Log(LogLevelLocal.Error,
                            $"Unexpected handshake opcode: {opcode}. Disconnecting.");
                        tcpClient.Close();
                        continue;
                    }

                    string username = reader.ReadMessage();
                    string uidString = reader.ReadMessage();
                    string publicKeyBase64 = reader.ReadMessage();

                    Log(LogLevelLocal.Debug, "[SERVER] Handshake received:");
                    Log(LogLevelLocal.Debug, $"  → Username: {username}");
                    Log(LogLevelLocal.Debug, $"  → UID: {uidString}");
                    Log(LogLevelLocal.Debug,
                        $"  → Key fragment: {publicKeyBase64.Substring(0, 32)}…");

                    Guid uid = Guid.Parse(uidString);
                    byte[] derBytes = Convert.FromBase64String(publicKeyBase64);

                    using var rsa = RSA.Create();
                    rsa.ImportRSAPublicKey(derBytes, out _);

                    var client = new Client(tcpClient, username, uid)
                    {
                        PublicKeyDer = derBytes,
                        PublicKeyBase64 = publicKeyBase64
                    };
                    Users.Add(client);

                    Log(LogLevelLocal.Info,
                        $"Client connected: {username} ({uid})");
                    Log(LogLevelLocal.Info,
                        $"[SERVER] User count: {Users.Count}");
                    foreach (var u in Users)
                        Log(LogLevelLocal.Debug,
                            $"  → {u.Username} ({u.UID})");

                    Task.Run(() => client.ListenForMessages());
                    BroadcastConnection();
                }
                catch (Exception ex)
                {
                    Log(LogLevelLocal.Error,
                        $"[SERVER] Handshake error: {ex.Message}");
                }
            }
        }
    }
}
