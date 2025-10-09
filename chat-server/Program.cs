/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 9th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace chat_server
{
    /// <summary>
    /// Application entry point and central dispatcher.
    /// Manages listener lifecycle, client registration, broadcasting,
    /// and packet framing/unframing.
    /// </summary>
    public static class Program
    {
        private static TcpListener _listener = default!;

        ////<summary>Synchronization primitive used to block the main thread until a shutdown is triggered.</summary>
        private static readonly ManualResetEventSlim _shutdownEvent = new(false);

        /// <summary>Thread-safe list of all connected clients.</summary>
        public static readonly List<Client> Users = new();

        /// <summary>Culture code for localization (en or fr).</summary>
        public static string AppLanguage = "en";

        /// <summary>Reserved system UID for server-originated packets.</summary>
        public static readonly Guid SystemUID = Guid.Parse("00000000-0000-0000-0000-000000000001");

        /// <summary>
        /// Initializes console, localization, listener and waits for shutdown.
        /// </summary>
        public static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                Shutdown();
                _shutdownEvent.Set();
            };

            // Determines language and initializes resource manager
            string twoLetterlanguageCode = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
            AppLanguage = (twoLetterlanguageCode == "fr") ? "fr" : "en";
            LocalizationManager.Initialize(AppLanguage);

            DisplayBanner();
            int port = GetPortFromUser();

            try
            {
                StartServerListener(port);
                _shutdownEvent.Wait();
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ServerStartFailed", ServerLogLevel.Error, port, ex.Message);
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Broadcasts the current connected users list (roster) to every connected client.
        /// Excludes sending to self in each loop iteration.
        /// </summary>
        public static void BroadcastConnection()
        {
            List<Client> lstConnectedClientsSnapshot;
            lock (Users) lstConnectedClientsSnapshot = Users.ToList();

            foreach (var user in lstConnectedClientsSnapshot)
            {
                foreach (var peerUser in lstConnectedClientsSnapshot)
                {
                    if (peerUser.UID == user.UID || !peerUser.ClientSocket.Connected)
                        continue;

                    var packetBuilder = new PacketBuilder();
                    packetBuilder.WriteOpCode((byte)ServerPacketOpCode.ConnectionBroadcast);
                    packetBuilder.WriteUid(user.UID);
                    packetBuilder.WriteString(user.Username);
                    packetBuilder.WriteString(user.PublicKeyBase64 ?? string.Empty);

                    byte[] framedPacket = Frame(packetBuilder.GetPacketBytes());
                    try
                    {
                        peerUser.ClientSocket.GetStream().Write(framedPacket, 0, framedPacket.Length);
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("RosterSendFailed", ServerLogLevel.Error, user.Username, peerUser.Username, ex.Message);
                    }
                }
            }

            ServerLogger.LogLocalized("RosterBroadcastComplete", ServerLogLevel.Debug);
        }

        /// <summary>
        /// Removes the given UID from the connected users list and notifies all clients.
        /// </summary>
        /// <param name="uid">UID of the disconnected client.</param>
        public static void BroadcastDisconnect(string uid)
        {
            List<Client> lstConnectedClientsSnapshot;
            lock (Users) lstConnectedClientsSnapshot = Users.ToList();

            var goneUser = lstConnectedClientsSnapshot.FirstOrDefault(u => u.UID.ToString() == uid);
            if (goneUser != null)
                lock (Users) Users.Remove(goneUser);

            foreach (var peerUser in lstConnectedClientsSnapshot)
            {
                if (!peerUser.ClientSocket.Connected) continue;

                var packetBuilder = new PacketBuilder();
                packetBuilder.WriteOpCode((byte)ServerPacketOpCode.DisconnectNotify);
                packetBuilder.WriteUid(Guid.Parse(uid));

                byte[] framedPacket = Frame(packetBuilder.GetPacketBytes());
                try
                {
                    peerUser.ClientSocket.GetStream().Write(framedPacket, 0, framedPacket.Length);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("DisconnectNotifyFailed", ServerLogLevel.Warn, peerUser.Username, ex.Message);
                }
            }

            ServerLogger.LogLocalized("UserDisconnected", ServerLogLevel.Info, uid);
        }

        /// <summary>
        /// Broadcasts a plaintext message to every client except the sender.
        /// </summary>
        /// <param name="message">Original text message.</param>
        /// <param name="senderId">UID of the sending client.</param>
        public static void BroadcastPlainMessage(string message, Guid senderId)
        {
            List<Client> snapshot;
            lock (Users) snapshot = Users.ToList();

            var sender = snapshot.FirstOrDefault(u => u.UID == senderId);
            string name = sender?.Username ?? "Unknown";
            ServerLogger.LogLocalized("PlainMessageBroadcast", ServerLogLevel.Debug, name, message);

            var packetBuilder = new PacketBuilder();
            packetBuilder.WriteOpCode((byte)ServerPacketOpCode.PlainMessage);
            packetBuilder.WriteUid(senderId);
            packetBuilder.WriteUid(Guid.Empty);
            packetBuilder.WriteString(message);

            byte[] framedPacket = Frame(packetBuilder.GetPacketBytes());
            foreach (var peerUser in snapshot)
            {
                if (peerUser.UID == senderId || !peerUser.ClientSocket.Connected) continue;
                try
                {
                    peerUser.ClientSocket.GetStream().Write(framedPacket, 0, framedPacket.Length);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("PlainMessageSendFailed", ServerLogLevel.Warn, peerUser.Username, ex.Message);
                }
            }
        }

        /// <summary>
        /// Broadcasts a client's public key to all other connected clients.
        /// </summary>
        /// <param name="sender">Source client for the key.</param>
        public static void BroadcastPublicKeyToOthers(Client sender)
        {
            List<Client> lstConnectedUsersSnapshot;
            lock (Users) lstConnectedUsersSnapshot = Users.ToList();

            foreach (var peerUser in lstConnectedUsersSnapshot)
            {
                if (peerUser.UID == sender.UID || !peerUser.ClientSocket.Connected) continue;

                var packetBuilder = new PacketBuilder();
                packetBuilder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
                packetBuilder.WriteUid(sender.UID);
                packetBuilder.WriteString(sender.PublicKeyBase64 ?? string.Empty);

                byte[] framedPacket = Frame(packetBuilder.GetPacketBytes());
                try
                {
                    peerUser.ClientSocket.GetStream().Write(framedPacket, 0, framedPacket.Length);
                    ServerLogger.LogLocalized("PublicKeyBroadcast", ServerLogLevel.Debug, sender.Username, peerUser.Username);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("PublicKeyBroadcastFail", ServerLogLevel.Error, peerUser.Username, ex.Message);
                }
            }
        }

        /// <summary>Displays localized startup banner.</summary>
        private static void DisplayBanner()
        {
            Console.WriteLine("╔═══════════════════════════════════╗");
            Console.WriteLine("║        WPF Chat Server 1.0        ║");
            Console.WriteLine("╚═══════════════════════════════════╝");
            Console.WriteLine(LocalizationManager.GetString("BannerLine1"));
            Console.WriteLine(LocalizationManager.GetString("BannerLine2"));
        }


        /// <summary>
        /// Wraps a raw packet body with a 4-byte big-endian length prefix.
        /// This helps the receiver know how many bytes to read.
        /// </summary>
        /// <param name="body">Raw packet body bytes.</param>
        /// <returns>Framed packet bytes.</returns>
        public static byte[] Frame(byte[] body)
        {
            // Converts the body length to big-endian format (network order)
            byte[] prefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(body.Length));

            // Creates a new byte array to hold the prefix + body
            var framedPacket = new byte[prefix.Length + body.Length];

            // Copies the 4-byte prefix to the beginning of the array
            Buffer.BlockCopy(prefix, 0, framedPacket, 0, prefix.Length);

            // Copies the body bytes right after the prefix
            Buffer.BlockCopy(body, 0, framedPacket, prefix.Length, body.Length);

            // Returns the final framed packet
            return framedPacket;
        }


        /// <summary>
        /// Prompts the user to enter a TCP port number, with timeout and basic validation.
        /// </summary>
        /// <returns>Chosen port between 1000 and 65535.</returns>
        private static int GetPortFromUser()
        {
            int defaultPort = 7123;

            // Asks the user to enter a port number
            Console.Write(LocalizationManager.GetString("PortPrompt") + " ");

            // Waits up to 7 seconds for input
            string input = ReadLineWithTimeout(7000);

            // If input is valid and within range, uses it
            if (!string.IsNullOrWhiteSpace(input) &&
                int.TryParse(input, out int p) &&
                p >= 1000 && p <= 65535)
            {
                return p;
            }

            // If input is invalid, asks if the user wants to use the default port
            Console.Write(LocalizationManager.GetString("InvalidPortPrompt"));
            string? confirm = Console.ReadLine()?.ToLowerInvariant();

            // If user confirms, returns default port; otherwise cancels startup
            return (confirm == "y" || confirm == "o") ? defaultPort
                                                      : throw new OperationCanceledException();
        }


        /// <summary>
        /// Performs the handshake, registers the client, broadcasts the connected users list, and starts packet loop.
        /// </summary>
        /// <param name="tcpClient">Newly accepted TCP client.</param>
        private static void HandleNewClient(TcpClient tcpClient)
        {
            var endpoint = tcpClient.Client.RemoteEndPoint?.ToString() ?? "Unknown";
            ServerLogger.LogLocalized("IncomingConnection", ServerLogLevel.Info, endpoint);

            try
            {
                var netStream = tcpClient.GetStream();
                var packetReaderNetStream = new PacketReader(netStream);

                // Unframe: reads length prefix and payload
                int bodyLength = packetReaderNetStream.ReadInt32NetworkOrder();
                byte[] payload = packetReaderNetStream.ReadExact(bodyLength);

                // Parses handshake packet
                using var ms = new MemoryStream(payload);
                var packetReader = new PacketReader(ms);
                var opcode = (ServerPacketOpCode)packetReader.ReadByte();
                if (opcode != ServerPacketOpCode.Handshake)
                {
                    ServerLogger.LogLocalized("UnexpectedOpcode", ServerLogLevel.Error, (byte)opcode);
                    tcpClient.Close();
                    return;
                }

                string username = packetReader.ReadString();
                Guid uid = packetReader.ReadUid();
                string publicKeyB64 = packetReader.ReadString();

                // Registers client
                var client = new Client(tcpClient, username, uid)
                {
                    PublicKeyBase64 = publicKeyB64,
                    PublicKeyDer = Convert.FromBase64String(publicKeyB64)
                };
                lock (Users) Users.Add(client);

                ServerLogger.LogLocalized("ClientConnected", ServerLogLevel.Info, username, uid);
                BroadcastConnection();

                /// <summary>
                /// Starts per-client packet loop in a separate task to avoid blocking the main thread.
                /// This allows the server to continue accepting new clients while each client is handled independently.
                /// </summary>
                _ = Task.Run(() => client.ListenForPackets());
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("HandleNewClientError", ServerLogLevel.Error, ex.Message);
                try { tcpClient.Close(); } catch { }
            }
        }

        /// <summary>
        /// Reads a line from the console, but only waits for a limited time.
        /// Useful to avoid blocking the program if the user doesn't respond.
        /// </summary>
        /// <param name="timeoutMs">Maximum time to wait in milliseconds.</param>
        /// <returns>User input or an empty string if timeout occurs.</returns>
        private static string ReadLineWithTimeout(int timeoutMs)
        {
            string? result = null;

            // Starts a background task to read input from the console
            Task.Run(() => result = Console.ReadLine())

                // Waits for the task to complete or timeout
                .Wait(timeoutMs);

            // Returns the input if available, or an empty string if timed out
            return result ?? string.Empty;
        }


        /// <summary>
        /// Relays an encrypted payload to a specific recipient.
        /// </summary>
        /// <param name="cipherB64">Base64 ciphertext string.</param>
        /// <param name="senderId">UID of the sender.</param>
        /// <param name="recipientId">UID of the recipient.</param>
        public static void RelayEncryptedMessageToAUser(string cipherB64, Guid senderId, Guid recipientId)
        {
            List<Client> lstConnectedUsersSnapshot;
            lock (Users) lstConnectedUsersSnapshot = Users.ToList();

            var recipient = lstConnectedUsersSnapshot.FirstOrDefault(u => u.UID == recipientId);
            if (recipient == null || !recipient.ClientSocket.Connected)
            {
                ServerLogger.LogLocalized("EncryptedDeliverFailed", ServerLogLevel.Warn, senderId, recipientId);
                return;
            }

            ServerLogger.LogLocalized("EncryptedMessageRelay", ServerLogLevel.Debug, senderId, recipientId);

            var packetBuilder = new PacketBuilder();
            packetBuilder.WriteOpCode((byte)ServerPacketOpCode.EncryptedMessage);
            packetBuilder.WriteUid(senderId);
            packetBuilder.WriteUid(recipientId);
            // writes raw bytes
            byte[] cipher = Convert.FromBase64String(cipherB64);
            packetBuilder.WriteBytesWithLength(cipher);

            byte[] framedPacket = Frame(packetBuilder.GetPacketBytes());
            try
            {
                recipient.ClientSocket.GetStream().Write(framedPacket, 0, framedPacket.Length);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("EncryptedSendError", ServerLogLevel.Error, recipient.Username, ex.Message);
            }
        }

        /// <summary>
        /// Handles a public key request from one client to another.
        /// Finds the target user and sends their public key to the requester only.
        /// </summary>
        /// <param name="requesterId">UID of the client requesting the key.</param>
        /// <param name="targetId">UID of the client whose key is requested.</param>
        public static void RelayPublicKeyRequest(Guid requesterId, Guid targetId)
        {
            List<Client> lstConnectedUsersSnapshot;
            lock (Users) lstConnectedUsersSnapshot = Users.ToList();

            var targetUser = lstConnectedUsersSnapshot.FirstOrDefault(u => u.UID == targetId);
            var requestingUser = lstConnectedUsersSnapshot.FirstOrDefault(u => u.UID == requesterId);

            if (targetUser == null)
            {
                ServerLogger.LogLocalized("PublicKeyRequestTargetNotFound", ServerLogLevel.Warn, targetId);
                return;
            }

            if (requestingUser == null || !requestingUser.ClientSocket.Connected)
            {
                ServerLogger.LogLocalized("PublicKeyRequestRequesterNotConnected", ServerLogLevel.Warn, requesterId);
                return;
            }

            var packetBuilder = new PacketBuilder();
            packetBuilder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
            packetBuilder.WriteUid(targetUser.UID);
            packetBuilder.WriteString(targetUser.PublicKeyBase64 ?? string.Empty);
            packetBuilder.WriteUid(requesterId);

            byte[] framedPacket = Frame(packetBuilder.GetPacketBytes());

            try
            {
                var stream = requestingUser.ClientSocket.GetStream();
                stream.Write(framedPacket, 0, framedPacket.Length);
                stream.Flush();

                ServerLogger.LogLocalized("PublicKeyRequestSuccess", ServerLogLevel.Debug, targetUser.Username, requestingUser.Username);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("PublicKeyRequestSendError", ServerLogLevel.Error, ex.Message);
            }
        }

        /// <summary>
        /// Relays a single public-key response to the original requester.
        /// </summary>
        /// <param name="responderId">UID of the client who owns the key.</param>
        /// <param name="publicKeyB64">Base64‐encoded public key.</param>
        /// <param name="requesterId">UID of the client requesting the key.</param>
        public static void RelayPublicKeyToUser(Guid responderId, string publicKeyB64, Guid requesterId)
        {
            List<Client> lstConnectedUsersSnapshot;
            lock (Users) lstConnectedUsersSnapshot = Users.ToList();

            var requester = lstConnectedUsersSnapshot.FirstOrDefault(u => u.UID == requesterId);
            if (requester == null || !requester.ClientSocket.Connected)
            {
                ServerLogger.LogLocalized("PublicKeyDeliverFail", ServerLogLevel.Warn, requesterId);
                return;
            }

            var packetBuilder = new PacketBuilder();
            packetBuilder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
            packetBuilder.WriteUid(responderId);
            packetBuilder.WriteString(publicKeyB64);
            packetBuilder.WriteUid(requesterId);

            byte[] framedPacket = Frame(packetBuilder.GetPacketBytes());
            try
            {
                requester.ClientSocket.GetStream().Write(framedPacket, 0, framedPacket.Length);
                ServerLogger.LogLocalized("PublicKeyDelivered", ServerLogLevel.Debug, responderId, requesterId);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("PublicKeyDeliverError", ServerLogLevel.Error, ex.Message);
            }
        }

        /// <summary>
        /// Notifies all clients of server shutdown and closes connections.
        /// </summary>
        public static void Shutdown()
        {
            ServerLogger.LogLocalized("ShutdownStart", ServerLogLevel.Info);

            List<Client> lstConnectedUsersSnapshot;
            lock (Users) lstConnectedUsersSnapshot = Users.ToList();

            foreach (var client in lstConnectedUsersSnapshot)
            {
                try
                {
                    var packetBuilder = new PacketBuilder();
                    packetBuilder.WriteOpCode((byte)ServerPacketOpCode.DisconnectClient);
                    packetBuilder.WriteUid(SystemUID);

                    byte[] framedPacket = Frame(packetBuilder.GetPacketBytes());
                    if (client.ClientSocket.Connected)
                        client.ClientSocket.GetStream().Write(framedPacket, 0, framedPacket.Length);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("ShutdownNotifyFail", ServerLogLevel.Error, client.Username, ex.Message);
                }
            }

            ServerLogger.LogLocalized("ShutdownComplete", ServerLogLevel.Info);
        }

        /// <summary>
        /// Starts the TCP listener on the specified port and launches a background task
        /// that continuously accepts incoming client connections.
        /// Each accepted client is handled in its own task to keep the server responsive.
        /// </summary>
        /// <param name="port">TCP port to bind and listen on.</param>
        public static void StartServerListener(int port)
        {
            // Creates a TCP listener that listens on all network interfaces
            _listener = new TcpListener(IPAddress.Any, port);

            // Starts the listener to begin accepting connections
            _listener.Start();

            // Logs that the server is now listening
            ServerLogger.LogLocalized("ServerStartedOnPort", ServerLogLevel.Info, port);

            // Runs the accept loop in a separate task so the main thread stays free
            Task.Run(async () =>
            {
                // Keeps accepting clients until shutdown is requested
                while (!_shutdownEvent.IsSet)
                {
                    try
                    {
                        // Waits asynchronously for a new client to connect
                        var tcpClient = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);

                        // Handles the new client in its own task to avoid blocking the loop
                        _ = Task.Run(() => HandleNewClient(tcpClient));
                    }
                    catch (Exception ex)
                    {
                        // Logs any error that occurs while accepting clients
                        ServerLogger.LogLocalized("AcceptLoopError", ServerLogLevel.Error, ex.Message);
                    }
                }
            });
        }

    }
}

