/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 23th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace chat_server
{
    public class Program
    {
        static internal List<Client> Users = new List<Client>();
        static TcpListener Listener;

        private static bool _exitByCtrlC;
        /// <summary>
        /// • Initializes localization based on OS culture.  
        /// • Configures console output to UTF-8.  
        /// • Handles Ctrl+C for graceful shutdown.  
        /// • Registers ProcessExit handler for normal shutdown.  
        /// • Displays banner and prompts for TCP port.  
        /// • Starts TcpListener on loopback with the chosen port.  
        /// • Accepts incoming clients in a continuous loop.  
        /// • Adds each client to Users and broadcasts roster updates.  
        /// </summary>
        public static void Main(string[] args)
        {
            // Initializes localization based on OS culture
            string twoLetterLanguageCode = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            string uiLang = twoLetterLanguageCode.Equals("fr", StringComparison.OrdinalIgnoreCase)
                              ? "fr"
                              : "en";
            LocalizationManager.Initialize(uiLang);

            // Configures console for UTF-8 output
            Console.OutputEncoding = Encoding.UTF8;

            // Handles Ctrl+C for graceful shutdown
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                _exitByCtrlC = true;
                Shutdown();
                Environment.Exit(0);
            };

            // Registers ProcessExit handler for normal shutdown
            SetupShutdownHooks();

            // Displays banner and prompt user for port
            DisplayBanner();
            int port = GetPortFromUser();

            try
            {
                Users = new List<Client>();
                Listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
                Listener.Start();
                Console.WriteLine(
                  string.Format(
                    LocalizationManager.GetString("ServerStartedOnPort"),
                    port));

                // Accepts incoming clients and broadcasts roster updates
                while (true)
                {
                    TcpClient tcp = Listener.AcceptTcpClient();
                    var client = new Client(tcp);

                    Users.Add(client);
                    BroadcastRoster();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nFailed to start server on port {port}: {ex.Message}");
                Console.WriteLine("Exiting...");
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Removes the specified user from the server roster
        /// and broadcasts a framed DisconnectNotify packet to all remaining clients.
        /// Packet layout:
        ///   [4-byte big-endian length prefix]
        ///   [1-byte opcode: DisconnectNotify]
        ///   [16-byte UID of the disconnected user]
        ///   [4-byte string length][UTF-8 bytes of username]
        /// </summary>
        /// <param name="disconnectedUserId">UID of the client who disconnected.</param>
        public static void BroadcastDisconnectNotify(Guid disconnectedUserId)
        {
            // Use the provided Guid directly
            Guid disconnectedGuid = disconnectedUserId;

            // Takes a snapshot of all current users
            var snapshot = Users.ToList();

            /// <summary>
            /// FirstOrDefault returns a nullable Client if no match is found,
            /// so we declare goneUser as Client? to reflect that.
            /// </summary>
            Client? goneUser = snapshot.FirstOrDefault(u => u.UID == disconnectedGuid);

            /// <summary>
            /// Safely guards the removal logic
            /// </summary>
            if (goneUser is not null)
            {
                lock (Users)
                    Users.Remove(goneUser);
            }

            // Chooses a safe username fallback:
            // use disconnected GUID string when username is unavailable
            string username = goneUser?.Username ?? disconnectedUserId.ToString();

            /// <summary>
            /// Builds the framed DisconnectNotify for each remaining client
            /// and sends it if their socket is connected.
            /// </summary>
            foreach (var listener in snapshot)
            {
                if (!listener.ClientSocket.Connected)
                    continue;

                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.DisconnectNotify);
                builder.WriteUid(disconnectedGuid);
                builder.WriteString(username);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                try
                {
                    listener.ClientSocket.Client.Send(framedPacket);
                    ServerLogger.LogLocalized("DisconnectNotifySuccess", ServerLogLevel.Debug,
                        listener.Username);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("DisconnectNotifyFailed", ServerLogLevel.Warn,
                        listener.Username, ex.Message);
                }
            }

            ServerLogger.LogLocalized("UserDisconnected", ServerLogLevel.Info, username);
        }

        /// <summary>
        /// • Builds and sends a framed ForceDisconnectClient packet to every connected client  
        /// • Packet structure: [4-byte length][1-byte opcode][16-byte target UID]  
        /// • Forces each client to call its Disconnect sequence upon decoding  
        /// </summary>
        public static void BroadcastForceDisconnect()
        {
            foreach (var user in Users.Where(u => u.ClientSocket.Connected))
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.ForceDisconnectClient);
                builder.WriteUid(user.UID);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                try
                {
                    user.ClientSocket.Client.Send(framedPacket);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("BroadcastForceDisconnectFailed",
                        ServerLogLevel.Warn, user.Username, ex.Message);
                }
            }

            ServerLogger.LogLocalized("BroadcastForceDisconnectSuccess",
                ServerLogLevel.Debug, Users.Count.ToString());
        }

        /// <summary>
        /// Broadcasts the full roster of connected users to every client.
        /// </summary>
        public static void BroadcastRoster()
        {
            // Creates a snapshot of the current user list to avoid concurrent modifications
            var snapshot = Users.ToList();

            foreach (var recipient in snapshot)
            {
                try
                {
                    // Start building a RosterBroadcast packet
                    var builder = new PacketBuilder();
                    builder.WriteOpCode((byte)ServerPacketOpCode.RosterBroadcast);

                    // Writes the total number of users as a string
                    builder.WriteString(snapshot.Count.ToString());

                    // Appends each user’s UID, username, and public key (or empty if missing)
                    foreach (var target in snapshot)
                    {
                        builder.WriteUid(target.UID);
                        builder.WriteString(target.Username);
                        builder.WriteString(target.PublicKeyBase64 ?? string.Empty);
                    }

                    // Extracts the raw packet bytes
                    byte[] payload = builder.GetPacketBytes();

                    // Frames the payload with a 4-byte big-endian length prefix
                    byte[] framedPacket = Frame(payload);

                    // Sends the framed packet to the recipient’s socket
                    recipient.ClientSocket.Client.Send(framedPacket);

                    // Logs success for this recipient
                    ServerLogger.LogLocalized("RosterSendSuccess", ServerLogLevel.Debug,
                        recipient.Username);
                }
                catch (Exception ex)
                {
                    // Logs any failure to deliver this roster packet
                    ServerLogger.LogLocalized("RosterSendFailed", ServerLogLevel.Error,
                        recipient.Username, ex.Message);
                }
            }
        }

        /// <summary>
        /// Broadcasts a plain-text chat message from one client to all connected clients.
        /// Packet structure:
        ///   [4-byte big-endian length]
        ///   [1-byte opcode: PlainMessage]
        ///   [16-byte sender UID]
        ///   [16-byte recipient UID]
        ///   [4-byte message length][UTF-8 message bytes]
        /// </summary>
        /// <param name="messageText">The message content to broadcast.</param>
        /// <param name="senderUid">Unique identifier of the message sender.</param>
        public static void BroadcastPlainMessage(string messageText, Guid senderUid)
        {
            var targets = Users.ToList();  // snapshot to avoid concurrent modifications

            foreach (var target in targets)
            {
                if (!target.ClientSocket.Connected)
                    continue;

                // Build the packet
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.PlainMessage);
                builder.WriteUid(senderUid);     // sender’s UID
                builder.WriteUid(target.UID);    // recipient UID placeholder
                builder.WriteString(messageText);// length+UTF-8 bytes

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);  // prepend 4-byte length

                try
                {
                    target.ClientSocket.Client.Send(framedPacket);
                    ServerLogger.LogLocalized("MessageRelaySuccess", ServerLogLevel.Debug, target.Username);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("MessageRelayFailed", ServerLogLevel.Warn, target.Username, ex.Message);
                }
            }
        }

        /// <summary>
        /// Writes the server banner and startup instructions to the console.
        /// </summary>
        static void DisplayBanner()
        {
            Console.WriteLine("╔═══════════════════════════════════╗");
            Console.WriteLine("║        WPF Chat Server 1.0        ║");
            Console.WriteLine("╚═══════════════════════════════════╝");
            Console.WriteLine(LocalizationManager.GetString("BannerLine1"));
            Console.WriteLine(LocalizationManager.GetString("BannerLine2"));
        }

        /// <summary>
        /// Frames a raw payload with a network-order length prefix for packet transmission.
        /// </summary>
        /// <param name="payload">Raw packet payload bytes.</param>
        /// <returns>Framed packet ready for network send.</returns>
        static byte[] Frame(byte[] payload)
        {
            using MemoryStream memoryStream = new MemoryStream();
            using BinaryWriter binaryWriter = new BinaryWriter(memoryStream);
            binaryWriter.Write(IPAddress.HostToNetworkOrder(payload.Length));
            binaryWriter.Write(payload);
            return memoryStream.ToArray();
        }

        /// <summary>
        /// Prompts the user to enter a valid TCP port or fallback to default.
        /// </summary>
        /// <returns>Valid port number to use</returns>
        static int GetPortFromUser()
        {
            int defaultPort = 7123;
            int chosenPort = defaultPort;

            Console.WriteLine(LocalizationManager.GetString("PortPrompt"));
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
            string input = "";
            var task = Task.Run(() => input = Console.ReadLine());
            bool completed = task.Wait(timeoutMs);
            return completed ? input : "";
        }

        /// <summary>
        /// Relays an encrypted payload from one client to another specific client.
        /// Constructs a framed packet (4-byte length prefix + payload) containing:
        ///   • opcode (EncryptedMessage)
        ///   • sender UID
        ///   • recipient UID
        ///   • length-prefixed ciphertext bytes
        /// Then sends it via the raw socket API and logs success or failure.
        /// </summary>
        /// <param name="cipherB64">Base64 string of the encrypted payload.</param>
        /// <param name="senderUid">Unique identifier of the sending client.</param>
        /// <param name="recipientUid">Unique identifier of the receiving client.</param>
        public static void RelayEncryptedMessageToAUser(string cipherB64, Guid senderUid, Guid recipientUid)
        {
            List<Client> snapshot;
            snapshot = Users.ToList();

            var recipient = snapshot.FirstOrDefault(u => u.UID == recipientUid);
            if (recipient?.ClientSocket.Connected == true)
            {
                byte[] cipherBytes = Convert.FromBase64String(cipherB64);

                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.EncryptedMessage);
                builder.WriteUid(senderUid);
                builder.WriteUid(recipientUid);
                builder.WriteBytesWithLength(cipherBytes);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                try
                {
                    recipient.ClientSocket.Client.Send(framedPacket);
                    ServerLogger.LogLocalized("EncryptedMessageRelaySuccess",
                        ServerLogLevel.Debug, recipient.Username);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("EncryptedMessageRelayFailed",
                        ServerLogLevel.Warn, recipient.Username, ex.Message);
                }
            }
        }

        /// <summary>
        /// Relays a public key request from one client to another specific client.
        /// Constructs a framed packet (4-byte length prefix + payload) containing:
        ///   • opcode (PublicKeyRequest)
        ///   • requester UID
        ///   • target UID
        /// Then sends it via the raw socket API and logs success or failure.
        /// </summary>
        /// <param name="requesterUid">Unique identifier of the requesting client.</param>
        /// <param name="targetUid">Unique identifier of the client whose key is requested.</param>
        public static void RelayPublicKeyRequest(Guid requesterUid, Guid targetUid)
        {
            List<Client> snapshot;
            snapshot = Users.ToList();

            var target = snapshot.FirstOrDefault(u => u.UID == targetUid);
            if (target?.ClientSocket.Connected == true)
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyRequest);
                builder.WriteUid(requesterUid);
                builder.WriteUid(targetUid);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                try
                {
                    target.ClientSocket.Client.Send(framedPacket);
                    ServerLogger.LogLocalized("PublicKeyRequestRelaySuccess", 
                        ServerLogLevel.Debug, target.Username);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("PublicKeyRequestRelayFailed",
                        ServerLogLevel.Warn, target.Username, ex.Message);
                }
            }
        }

        /// <summary>
        /// Sends a PublicKeyResponse packet back to the original requester.
        /// Packet structure:
        ///   [4-byte length prefix]
        ///   [1-byte opcode: PublicKeyResponse]
        ///   [16-byte origin UID]
        ///   [4-byte byte-array length][DER-encoded RSA public key bytes]
        ///   [16-byte requester UID]
        /// </summary>
        /// <param name="originUid">UID of the client providing its public key.</param>
        /// <param name="publicKeyDer">The RSA public key in DER-encoded byte array format.</param>
        /// <param name="requesterUid">UID of the client that requested the key.</param>
        public static void RelayPublicKeyToUser(Guid originUid, byte[] publicKeyDer, Guid requesterUid)
        {
            var snapshot = Users.ToList();
            var target = snapshot.FirstOrDefault(u => u.UID == requesterUid);
            if (target?.ClientSocket.Connected != true)
                return;

            var builder = new PacketBuilder();
            builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
            builder.WriteUid(originUid);
            builder.WriteBytesWithLength(publicKeyDer);
            builder.WriteUid(requesterUid);

            byte[] payload = builder.GetPacketBytes();
            byte[] framedPacket = Frame(payload);

            try
            {
                target.ClientSocket.Client.Send(framedPacket);
                ServerLogger.LogLocalized("PublicKeyResponseRelaySuccess",
                    ServerLogLevel.Debug, target.Username);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("PublicKeyResponseRelayFailed",
                    ServerLogLevel.Warn, target.Username, ex.Message);
            }
        }

        /// <summary>
        /// • Registers handlers for Ctrl+C and normal process exit  
        /// • On normal exit, broadcasts a framed ForceDisconnectClient packet to all clients  
        /// • Waits up to 500 ms to let packets traverse the network  
        /// • Skips notification on Ctrl+C for immediate shutdown  
        /// </summary>
        private static void SetupShutdownHooks()
        {
            // Captures CTRL+C and prevents immediate termination
            Console.CancelKeyPress += (sender, e) =>
            {
                _exitByCtrlC = true;
                e.Cancel = true;
                Environment.Exit(0);
            };

            // Fires when the process is exiting normally
            AppDomain.CurrentDomain.ProcessExit += (sender, e) =>
            {
                if (_exitByCtrlC)
                    return;

                BroadcastForceDisconnect();
                Thread.Sleep(500);
            };
        }

        /// <summary>
        /// Signals all clients to disconnect and shuts down the server gracefully.
        /// </summary>
        public static void Shutdown()
        {
            Console.WriteLine(LocalizationManager.GetString("ServerShutdown"));
            BroadcastPlainMessage("/disconnect", Guid.Empty);
            Console.WriteLine(LocalizationManager.GetString("ServerShutdownComplete"));
        }
    }
}
