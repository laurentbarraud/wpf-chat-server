/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 17th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using Microsoft.VisualBasic.ApplicationServices;
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

        public static void Main(string[] args)
        {
            // Initialize localization based on OS culture.
            // If the two-letter code is “fr”, use French; otherwise use English.
            string osTwoLetter = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            string uiLang = osTwoLetter.Equals("fr", StringComparison.OrdinalIgnoreCase)
                                ? "fr"
                                : "en";
            LocalizationManager.Initialize(uiLang);

            Console.OutputEncoding = Encoding.UTF8;

            // Graceful shutdown on Ctrl+C
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                Shutdown();
                Environment.Exit(0);
            };

            DisplayBanner();
            int port = GetPortFromUser();

            try
            {
                Users = new List<Client>();
                Listener = new TcpListener(IPAddress.Parse("127.0.0.1"), port);
                Listener.Start();
                Console.WriteLine(string.Format(LocalizationManager.GetString("ServerStartedOnPort"),
                    port));

                // Main loop: accepts incoming clients and broadcasts their connection
                while (true)
                {
                    var client = new Client(Listener.AcceptTcpClient());
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
        /// Removes the specified user from the server roster and notifies all remaining clients.
        /// Constructs a framed packet (4-byte length prefix + payload) containing:
        ///   • opcode (DisconnectNotify)
        ///   • UID of the disconnected user
        /// Then sends it via the raw socket API and logs success or failure for each recipient.
        /// </summary>
        /// <param name="disconnectedUserId">Unique identifier of the client who disconnected.</param>
        public static void BroadcastDisconnect(string disconnectedUserId)
        {
            // Snapshot users
            var snapshot = Users.ToList();

            // Tries to find the gone user
            Client goneUser = snapshot.FirstOrDefault(u => u.UID.ToString() == disconnectedUserId);

            // If found, removes from the live Users list
            if (goneUser != null)
            {
                lock (Users)
                    Users.Remove(goneUser);
            }

            // Prepares a safe username fallback
            string username = goneUser?.Username ?? disconnectedUserId;

            // Notifies each listener
            foreach (var listener in snapshot)
            {
                if (!listener.ClientSocket.Connected)
                    continue;

                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ServerPacketOpCode.DisconnectNotify);
                builder.WriteUid(Guid.Parse(disconnectedUserId));
                builder.WriteString(username);   // safe fallback

                // Frames the packet
                byte[] payload = builder.GetPacketBytes();
                int netLen = IPAddress.HostToNetworkOrder(payload.Length);
                byte[] lenBuf = BitConverter.GetBytes(netLen);

                try
                {
                    listener.ClientSocket.Client.Send(lenBuf);
                    listener.ClientSocket.Client.Send(payload);

                    ServerLogger.LogLocalized("DisconnectNotifySuccess", ServerLogLevel.Debug,
                        listener.Username);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("DisconnectNotifyFailed", ServerLogLevel.Warn,
                        listener.Username, ex.Message);
                }
            }

            // Logs the disconnection event once
            ServerLogger.LogLocalized("UserDisconnected", ServerLogLevel.Info, username);
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
