/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 14th, 2025</date>

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;

namespace chat_server
{
    public class Program
    {
        // Shared list of connected clients
        internal static List<Client> Users = new();

        // Listener for all incoming TCP connections
        static TcpListener listener;

        public static void Main(string[] args)
        {
            // Initializes localization based on OS culture (fr or en)
            string twoLetterLanguageCode = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            LocalizationManager.Initialize(twoLetterLanguageCode.Equals("fr", StringComparison.OrdinalIgnoreCase) ? "fr" : "en");

            Console.OutputEncoding = System.Text.Encoding.UTF8;

            // Handles Ctrl+C: stops listener and exits immediately
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                listener.Stop();
                Environment.Exit(0);
            };

            DisplayBanner();
            int portNumber = GetPortFromUser();

            try
            {
                // Starts listening on loopback
                listener = new TcpListener(IPAddress.Loopback, portNumber);
                listener.Start();
                Console.WriteLine(string.Format(LocalizationManager.GetString("ServerStartedOnPort"),
                        portNumber));

                // Accepts new clients continuously
                Task.Run(AcceptLoop);

                // Main thread blocks forever (or until Ctrl+C fires)
                Thread.Sleep(Timeout.Infinite);
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n" + string.Format(LocalizationManager.GetString("FailedToStartServerOnPort"),
                        portNumber, ex.Message));
                Console.WriteLine(LocalizationManager.GetString("Exiting..."));
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Runs in a background thread.
        /// Accepts TCP clients, generates a Client wrapper for each,
        /// and lets Client.cs handle handshake and packet loop.
        /// </summary>
        private static void AcceptLoop()
        {
            while (true)
            {
                TcpClient tcpClient;
                try
                {
                    tcpClient = listener.AcceptTcpClient();
                }
                catch (SocketException)
                {
                    // listener.Stop() was called on shutdown
                    break;
                }

                // Handles each client without blocking AcceptLoop()
                Task.Run(() =>
                {
                    try
                    {
                        // Client constructor performs handshake, roster update, and starts its own loop
                        new Client(tcpClient);
                    }
                    catch (Exception ex)
                    {
                        // Logs any handshake or initialization failure and closes socket
                        ServerLogger.LogLocalized("HandleNewClientError", ServerLogLevel.Error,
                            ex.Message);
                        try 
                        { 
                            tcpClient.Close(); 
                        } 
                        catch 
                        { 
                        
                        }
                    }
                });
            }
        }

        /// <summary>
        /// Broadcasts the full roster of connected users to every client.
        /// Builds a framed packet (4-byte length prefix + payload) for each user,
        /// then sends it via the raw socket API. Logs success or failure per send.
        /// </summary>
        public static void BroadcastConnection()
        {
            // Take a snapshot to avoid collection-modification during iteration
            List<Client> snapshot;
            //lock (Users)
                snapshot = Users.ToList();

            foreach (var broadcaster in snapshot)
            {
                foreach (var listener in snapshot)
                {
                    if (!listener.ClientSocket.Connected)
                        continue;

                    // Builds the roster packet
                    var builder = new PacketBuilder();
                    builder.WriteOpCode((byte)ServerPacketOpCode.ConnectionBroadcast);
                    builder.WriteUid(broadcaster.UID);
                    builder.WriteString(broadcaster.Username);
                    builder.WriteString(broadcaster.PublicKeyBase64 ?? string.Empty);

                    // Frames the payload with a 4-byte network-order length prefix
                    byte[] payload = builder.GetPacketBytes();
                    byte[] framedPacket = Frame(payload);

                    try
                    {
                        // Sends the framed packet via raw socket
                        listener.ClientSocket.Client.Send(framedPacket);
                        ServerLogger.LogLocalized("RosterSendSuccess", ServerLogLevel.Debug,
                            listener.Username);
                    }
                    catch (Exception ex)
                    {
                        // Logs any failure to deliver the roster packet
                        ServerLogger.LogLocalized("RosterSendFailed", ServerLogLevel.Error,
                            listener.Username, ex.Message);
                    }
                }
            }
        }

        /// <summary>
        /// Removes the specified user from the server roster and notifies all remaining clients.
        /// Constructs a framed packet (4-byte length prefix + payload) containing:
        ///   • opcode (DisconnectNotify)
        ///   • UID of the disconnected user
        /// Then sends it via the raw socket API and logs success or failure for each recipient.
        /// </summary>
        /// <param name="disconnectedUserId">Unique identifier of the client who disconnected.</param>
        public static void BroadcastDisconnect(string disconnectedUserId)
        {
            // Takes a snapshot of current users to avoid modifying the collection during iteration
            List<Client> snapshot;
            lock (Users)
                snapshot = Users.ToList();

            // Locates and removes the disconnected user from the live roster
            Client goneUser = snapshot.FirstOrDefault(u => u.UID.ToString() == disconnectedUserId);
            if (goneUser != null)
            {
                lock (Users)
                    Users.Remove(goneUser);
            }

            // Notifies each remaining client
            foreach (var listener in snapshot)
            {
                if (!listener.ClientSocket.Connected)
                    continue;

                // Builds the disconnect notification packet
                var packetBuilder = new PacketBuilder();
                packetBuilder.WriteOpCode((byte)ServerPacketOpCode.DisconnectNotify);
                packetBuilder.WriteUid(Guid.Parse(disconnectedUserId));
                packetBuilder.WriteString(goneUser.Username);

                // Frames the packet with a 4-byte network-order length prefix
                byte[] payload = packetBuilder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                try
                {
                    // Sends via the raw socket API
                    listener.ClientSocket.Client.Send(framedPacket);
                    ServerLogger.LogLocalized("DisconnectNotifySuccess", 
                        ServerLogLevel.Debug, listener.Username);
                }
                catch (Exception ex)
                {
                    // Logs any failure to deliver the notification
                    ServerLogger.LogLocalized("DisconnectNotifyFailed",  
                        ServerLogLevel.Warn, listener.Username, ex.Message);
                }
            }

            // Logs the overall disconnection event once
            string username = goneUser?.Username ?? "Unknown User";
            ServerLogger.LogLocalized("UserDisconnected", ServerLogLevel.Info,
                username);
        }


        /// <summary>
        /// Broadcasts a plain‐text chat message from one client to all connected clients.
        /// Constructs a framed packet (4-byte length prefix + payload) containing:
        ///   • opcode (PlainMessage)
        ///   • sender UID
        ///   • recipient UID placeholder
        ///   • UTF-8 message text
        /// Then sends it via the raw socket API and logs each delivery result.
        /// </summary>
        /// <param name="messageText">The message content to broadcast.</param>
        /// <param name="senderUid">Unique identifier of the message sender.</param>
        public static void BroadcastPlainMessage(string messageText, Guid senderUid)
        {
            // Snapshots the user list to avoid concurrent-modification
            List<Client> targets;
            lock (Users)
                targets = Users.ToList();

            foreach (var target in targets)
            {
                if (!target.ClientSocket.Connected)
                    continue;

                // Builds the packet
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.PlainMessage);
                builder.WriteUid(senderUid);       // sender’s UID
                builder.WriteUid(target.UID);      // recipient placeholder
                builder.WriteString(messageText);  // the actual message

                // Frames with 4-byte network-order length prefix
                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                try
                {
                    // Sends via raw socket
                    target.ClientSocket.Client.Send(framedPacket);
                    ServerLogger.LogLocalized("MessageRelaySuccess", ServerLogLevel.Debug,
                        target.Username);
                }
                catch (Exception ex)
                {
                    // Logs any failure
                    ServerLogger.LogLocalized("MessageRelayFailed", ServerLogLevel.Warn,
                        target.Username, ex.Message);
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
            lock (Users)
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
            lock (Users)
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
        /// Relays a public key response from one client back to the original requester.
        /// Constructs a framed packet (4-byte length prefix + payload) containing:
        ///   • opcode (PublicKeyResponse)
        ///   • origin UID
        ///   • Base64 public key string
        ///   • requester UID
        /// Then sends it via the raw socket API and logs success or failure.
        /// </summary>
        /// <param name="originUid">Unique identifier of the client sending its key.</param>
        /// <param name="keyBase64">Base64 string of the public key.</param>
        /// <param name="requesterUid">Unique identifier of the original requesting client.</param>
        public static void RelayPublicKeyToUser(Guid originUid, string keyBase64, Guid requesterUid)
        {
            List<Client> snapshot;
            lock (Users)
                snapshot = Users.ToList();

            var requester = snapshot.FirstOrDefault(u => u.UID == requesterUid);
            if (requester?.ClientSocket.Connected == true)
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
                builder.WriteUid(originUid);
                builder.WriteString(keyBase64);
                builder.WriteUid(requesterUid);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                try
                {
                    requester.ClientSocket.Client.Send(framedPacket);
                    ServerLogger.LogLocalized("PublicKeyResponseRelaySuccess",
                        ServerLogLevel.Debug, requester.Username);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("PublicKeyResponseRelayFailed", ServerLogLevel.Warn,
                        requester.Username, ex.Message);
                }
            }
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
