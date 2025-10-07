/// <file>Program.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 6th, 2025</date>

using chat_server;
using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;


/// <summary>
/// Serves as the application entry point.
/// Configures console encoding, registers shutdown handlers,
/// initializes localization, prompts for a listening port,
/// instantiates the TCP listener on that port, and starts the client-accept loop.
/// </summary>
public class Program
{
    /// <summary>Holds the server’s TCP listener instance; is instantiated before use.</summary>
    private static TcpListener _listener = default!;

    /// <summary>Blocks the Main thread until a shutdown is requested.</summary>
    private static readonly ManualResetEventSlim _shutdownEvent = new(false);

    /// <summary>Holds the connected clients; guarded for simple thread-safety when iterating.</summary>
    public static readonly List<Client> Users = new();

    /// <summary>Application language code (en or fr).</summary>
    public static string AppLanguage = "en";

    /// <summary>Reserved System UID used for server-originated packets.</summary>
    public static readonly Guid SystemUID = Guid.Parse("00000000-0000-0000-0000-000000000001");

    /// <summary>
    /// Application entry point.
    /// Sets up console, registers Ctrl+C handler, initializes localization,
    /// prompts for port, starts listener and waits for shutdown signal.
    /// </summary>
    public static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true;
            Shutdown();
            _shutdownEvent.Set();
        };

        string systemCulture = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
        AppLanguage = systemCulture == "fr" ? "fr" : "en";
        LocalizationManager.Initialize(AppLanguage);

        DisplayBanner();
        int portToListenTo = GetPortFromUser();

        try
        {
            _listener = new TcpListener(IPAddress.Any, portToListenTo);
            StartServerListener(portToListenTo);
            _shutdownEvent.Wait();
        }
        catch (Exception ex)
        {
            ServerLogger.LogLocalized($"{LocalizationManager.GetString("ServerStartFailed")} {portToListenTo}: {ex.Message}", ServerLogLevel.Error);
            ServerLogger.LogLocalized(LocalizationManager.GetString("Exiting"), ServerLogLevel.Info);
            Environment.Exit(1);
        }
    }

    /// <summary>
    /// Sends the list of connected users across all clients.
    /// </summary>
    public static void BroadcastConnection()
    {
        // Takes a stable snapshot of all connected clients
        List<Client> lstConnectedClientsSnapshot;
        lock (Users)
            lstConnectedClientsSnapshot = Users.ToList();

        // Broadcasts each user record to every other client
        foreach (var usr in lstConnectedClientsSnapshot)
        {
            // Builds a ConnectionBroadcast packet for the current user
            var packetConnectedUser = new PacketBuilder();
            packetConnectedUser.WriteOpCode((byte)ServerPacketOpCode.ConnectionBroadcast);
            packetConnectedUser.WriteUid(usr.UID);
            packetConnectedUser.WriteString(usr.Username);
            packetConnectedUser.WriteString(usr.PublicKeyBase64 ?? string.Empty);

            // Frames the packet for network transport
            byte[] packetBodyInBytes = packetConnectedUser.GetPacketBytes();
            byte[] framedPacketConnectedUser = Frame(packetBodyInBytes);

            // Sends the framed packet to all other clients
            foreach (var receiver in lstConnectedClientsSnapshot)
            {
                if (receiver.UID == usr.UID || !receiver.ClientSocket.Connected)
                    continue;

                try
                {
                    receiver.ClientSocket.GetStream().Write(framedPacketConnectedUser, 0, framedPacketConnectedUser.Length);
                }
                catch (Exception ex)
                {
                    ServerLogger.Log(
                        $"Failed to send roster entry of {usr.Username} to {receiver.Username}: {ex.Message}",
                        ServerLogLevel.Error
                    );
                }
            }
        }

        // Logs completion of the list of connected users broadcast
        ServerLogger.Log("[SERVER] Completed user list broadcast", ServerLogLevel.Debug);
    }

    /// <summary>
    /// Broadcasts a disconnect notification to all clients and logs each send.
    /// </summary>
    public static void BroadcastDisconnect(string uid)
    {
        List<Client> snapshot;
        lock (Users) snapshot = Users.ToList();

        var disconnectedUser = snapshot.FirstOrDefault(u => u.UID.ToString() == uid);
        if (disconnectedUser == null) return;

        foreach (var user in snapshot)
        {
            try
            {
                var packet = new PacketBuilder();
                packet.WriteOpCode((byte)ServerPacketOpCode.DisconnectNotify);
                packet.WriteUid(Guid.Parse(uid));

                byte[] framed = Frame(packet.GetPacketBytes());

                if (user.ClientSocket.Connected)
                {
                    user.ClientSocket.GetStream().Write(framed, 0, framed.Length);
                }

                ServerLogger.Log($"Notified {user.Username} of disconnection", ServerLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ServerLogger.Log($"Disconnect notification failed: {ex.Message}", ServerLogLevel.Error);
            }
        }
    }

    /// <summary>
    /// Broadcasts a plain text chat packet to every connected client except the sender.
    /// </summary>
    /// <param name="rawMessageContent">Plain text message to broadcast.</param>
    /// <param name="senderId">Sender user's UID.</param>
    public static void BroadcastPlainMessage(string rawMessageContent, Guid senderId)
    {
        // Takes a thread-safe snapshot of connected users
        List<Client> lstConnectedUsersSnapshot;
        lock (Users) lstConnectedUsersSnapshot = Users.ToList();

        var sendingUser = lstConnectedUsersSnapshot.FirstOrDefault(u => u.UID == senderId);
        string senderName = sendingUser?.Username ?? "Unknown";

        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        ServerLogger.Log($"[{timestamp}] Broadcast message from {senderName}: {rawMessageContent}", ServerLogLevel.Debug);

        // Builds packet: opcode, senderUid, recipientUid(empty), payload
        var packetMessage = new PacketBuilder();
        packetMessage.WriteOpCode((byte)ServerPacketOpCode.PlainMessage);
        packetMessage.WriteUid(senderId);
        packetMessage.WriteUid(Guid.Empty); // recipientId = empty for broadcast
        packetMessage.WriteString(rawMessageContent);

        // Builds a framed packet
        byte[] framedPacket = Frame(packetMessage.GetPacketBytes());

        foreach (var user in lstConnectedUsersSnapshot)
        {
            // Don't send back to sender
            if (user.UID == senderId) continue;

            if (!user.ClientSocket.Connected) continue;

            try
            {
                var networkStream = user.ClientSocket.GetStream();
                networkStream.Write(framedPacket, 0, framedPacket.Length);
                networkStream.Flush();
            }
            catch (Exception ex)
            {
                ServerLogger.Log($"Failed to send broadcast message to {user.Username}: {ex.Message}", ServerLogLevel.Debug);
            }
        }
    }

    /// <summary>Distributes sender's public key to other clients with framing.</summary>
    public static void BroadcastPublicKeyToOthers(Client sender)
    {
        List<Client> snapshot;
        lock (Users) snapshot = Users.ToList();

        foreach (var user in snapshot)
        {
            if (user.UID == sender.UID) continue;
            try
            {
                var packet = new PacketBuilder();
                packet.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
                packet.WriteUid(sender.UID);
                packet.WriteString(sender.PublicKeyBase64 ?? string.Empty);

                byte[] framed = Frame(packet.GetPacketBytes());

                if (user.ClientSocket.Connected)
                    user.ClientSocket.GetStream().Write(framed, 0, framed.Length);

                ServerLogger.Log($"Transmitted public key from {sender.Username} to {user.Username}", ServerLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ServerLogger.Log($"Public key transmission failed: {ex.Message}", ServerLogLevel.Error);
            }
        }

        ServerLogger.Log("[SERVER] Completed public key broadcast", ServerLogLevel.Debug);
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
    /// This helper constructs a length‑prefixed packet suitable for network transmission.
    /// It encodes the body length as a 4‑byte integer in network byte order (big‑endian),
    /// allocates a buffer large enough for the prefix plus body,
    /// copies the prefix and then the body into the buffer,
    /// and returns the framed byte array ready to send.
    /// </summary>
    /// <param name="body"></param>
    /// <returns>a framed byte array</returns>
    private static byte[] Frame(byte[] body)
    {
        // Computes the length of the raw packet body in bytes.
        int bodyLength = body.Length;

        // Converts the host-order integer length to network-order (big-endian)
        // and returns its 4-byte representation.
        byte[] lengthPrefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(bodyLength));

        // Allocates a new buffer that will contain the 4-byte length prefix
        // followed by the packet body.
        byte[] framed = new byte[lengthPrefix.Length + bodyLength];

        // Copies the 4-byte length prefix into the start of the framed buffer.
        Buffer.BlockCopy(lengthPrefix, 0, framed, 0, lengthPrefix.Length);

        // Copies the packet body immediately after the length prefix.
        Buffer.BlockCopy(body, 0, framed, lengthPrefix.Length, bodyLength);

        // Returns the assembled framed packet ready for transmission.
        return framed;
    }

    /// <summary>Prompts the user to enter a valid TCP port or fallback to default.</summary>
    private static int GetPortFromUser()
    {
        int defaultPort = 7123;
        int chosenPort = defaultPort;
        Console.Write(LocalizationManager.GetString("PortPrompt") + " ");
        string input = ReadLineWithTimeout(7000);

        if (!string.IsNullOrWhiteSpace(input))
        {
            if (int.TryParse(input, out int port) && port >= 1000 && port <= 65535)
            {
                chosenPort = port;
            }
            else
            {
                Console.Write(LocalizationManager.GetString("InvalidPortPrompt"));
                string? confirm = Console.ReadLine()?.Trim().ToLower();
                if (confirm == "y" || confirm == "o")
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
    /// Handles a newly accepted TCP client.
    /// Performs a framed read for the handshake, registers the client,
    /// broadcasts the roster and starts the client's message loop.
    /// </summary>
    private static void HandleNewClient(TcpClient tcpClient)
    {
        // Reads the remote endpoint for logging
        var endpoint = tcpClient.Client.RemoteEndPoint?.ToString() ?? "Unknown endpoint";
        ServerLogger.Log($"Incoming connection from {endpoint}", ServerLogLevel.Info);

        // Wraps the network stream in a PacketReader
        var netStream = tcpClient.GetStream();
        var reader = new PacketReader(netStream);

        try
        {
            // Reads the 4-byte network-order length prefix
            int bodyLength = reader.ReadInt32NetworkOrder();
            if (bodyLength <= 0)
                throw new InvalidDataException("Invalid handshake length");

            // Reads exactly bodyLength bytes as the handshake payload
            byte[] handshakePayload = reader.ReadExact(bodyLength);

            // Parses handshake payload from an in-memory stream
            using var ms = new MemoryStream(handshakePayload);
            var pr = new PacketReader(ms);

            // Reads and validates the handshake opcode
            byte rawOp = pr.ReadOpCode();
            var handshakeOp = (ServerPacketOpCode)rawOp;
            if (handshakeOp != ServerPacketOpCode.Handshake)
            {
                ServerLogger.Log($"Unexpected opcode {rawOp} during handshake", ServerLogLevel.Error);
                tcpClient.Close();
                return;
            }

            // Reads handshake fields: Username; UserId; PublicKeyBase64
            string username = pr.ReadString();
            Guid uid = pr.ReadUid();
            string publicKeyB64 = pr.ReadString();

            // Constructs and registers the new client
            var client = new Client(tcpClient, username, uid)
            {
                PublicKeyBase64 = publicKeyB64
            };
            lock (Users)
                Users.Add(client);

            // Logs the new connection and broadcasts the updated roster
            ServerLogger.Log($"Client connected: {username} ({uid})", ServerLogLevel.Info);
            BroadcastConnection();

            // Starts the client's message loop in a background task
            Task.Run(() => client.ListenForMessages());
        }
        catch (Exception ex)
        {
            ServerLogger.Log($"HandleNewClient failed: {ex.Message}", ServerLogLevel.Error);
            try { tcpClient.Close(); } catch { }
        }
    }


    internal static byte[] Program_Frame(byte[] body)
    {
        int bodyLength = body.Length;
        byte[] lengthPrefix = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(bodyLength));
        byte[] framed = new byte[lengthPrefix.Length + bodyLength];
        Buffer.BlockCopy(lengthPrefix, 0, framed, 0, lengthPrefix.Length);
        Buffer.BlockCopy(body, 0, framed, lengthPrefix.Length, bodyLength);
        return framed;
    }

    /// <summary>Reads a console line with a timeout.</summary>
    private static string ReadLineWithTimeout(int timeoutMs)
    {
        string? result = "";
        Task.Run(() => result = Console.ReadLine()).Wait(timeoutMs);
        return result ?? string.Empty;
    }

    /// <summary>
    /// Relays an encrypted chat packet to a single recipient. 
    /// Builds the framed packet and sends only to the client whose UID matches recipientId.
    /// </summary>
    /// <param name="rawMessageContent">Original message bytes or ciphertext represented as a string.</param>
    /// <param name="senderId">Sender user's UID.</param>
    /// <param name="recipientId">Recipient user's UID.</param>
    public static void RelayEncryptedMessageToAUser(string rawMessageContent, Guid senderId, Guid recipientId)
    {
        // Takes a thread-safe snapshot of the observable collection
        // of connected users in List<Client> format.
        List<Client> lstConnectedUsersSnapshot;
        lock (Users) lstConnectedUsersSnapshot = Users.ToList();

        var sendingUser = lstConnectedUsersSnapshot.FirstOrDefault(u => u.UID == senderId);
        string senderName = sendingUser?.Username ?? "Unknown";

        var targetUser = lstConnectedUsersSnapshot.FirstOrDefault(u => u.UID == recipientId);
        string targetName = targetUser?.Username ?? "Unknown";

        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        ServerLogger.Log($"[{timestamp}] Encrypted message from {senderName} to {targetName}", ServerLogLevel.Debug);

        // Builds packet: opcode, senderUid, recipientUid, payload
        var packetMessage = new PacketBuilder();
        packetMessage.WriteOpCode((byte)ServerPacketOpCode.EncryptedMessage);
        packetMessage.WriteUid(senderId);
        packetMessage.WriteUid(recipientId);
        packetMessage.WriteString(rawMessageContent);

        // Converts the packet into a byte array and prepends a 4-byte length header (big-endian)
        // to ensure proper framing over the network stream
        byte[] framedPacket = Frame(packetMessage.GetPacketBytes());

        // If target not found or not connected, logs and returns silently
        if (targetUser == null)
        {
            ServerLogger.Log($"Recipient {recipientId} not found for encrypted message from {senderName}", ServerLogLevel.Debug);
            return;
        }

        if (!targetUser.ClientSocket.Connected)
        {
            ServerLogger.Log($"Recipient {targetName} is not connected; cannot deliver encrypted message from {senderName}", ServerLogLevel.Debug);
            return;
        }

        try
        {
            var stream = targetUser.ClientSocket.GetStream();
            stream.Write(framedPacket, 0, framedPacket.Length);
            stream.Flush();
        }
        catch (Exception ex)
        {
            ServerLogger.Log($"Failed to send encrypted message to {targetName}: {ex.Message}", ServerLogLevel.Debug);
        }
    }

    /// <summary>
    /// Relays a user's public key to a specific requester only.
    /// Builds a PublicKeyResponse packet and sends it only to the client
    /// whose UID matches requesterId.
    /// </summary>
    /// <param name="requesterId">UID of the client who asked for the key.</param>
    /// <param name="targetId">UID of the client whose key is being requested.</param>
    public static void RelayPublicKeyRequest(Guid requesterId, Guid targetId)
    {
        List<Client> snapshot;
        lock (Users) snapshot = Users.ToList();

        var targetUser = snapshot.FirstOrDefault(u => u.UID == targetId);
        var requestingUser = snapshot.FirstOrDefault(u => u.UID == requesterId);

        if (targetUser == null)
        {
            ServerLogger.Log(
                $"PublicKeyRequest: target {targetId} not found",
                ServerLogLevel.Warn
            );
            return;
        }

        if (requestingUser == null || !requestingUser.ClientSocket.Connected)
        {
            ServerLogger.Log(
                $"PublicKeyRequest: requester {requesterId} not connected",
                ServerLogLevel.Warn
            );
            return;
        }

        // Build PublicKeyResponse: ResponderUserId; PublicKeyBase64; RequesterUserId
        var packet = new PacketBuilder();
        packet.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
        packet.WriteUid(targetUser.UID);
        packet.WriteString(targetUser.PublicKeyBase64 ?? string.Empty);
        packet.WriteUid(requesterId);

        byte[] framed = Frame(packet.GetPacketBytes());

        try
        {
            var stream = requestingUser.ClientSocket.GetStream();
            stream.Write(framed, 0, framed.Length);
            stream.Flush();

            ServerLogger.Log(
                $"Relayed public key of {targetUser.Username} to {requestingUser.Username}",
                ServerLogLevel.Debug
            );
        }
        catch (Exception ex)
        {
            ServerLogger.Log(
                $"RelayPublicKeyRequest failed: {ex.Message}",
                ServerLogLevel.Error
            );
        }
    }

    /// <summary>
    /// Sends a user's public key to a single client (the original requester).
    /// This is a one-off dispatch, unlike BroadcastPublicKeyToOthers which targets all peers.
    /// </summary>
    /// <param name="responderId">UID of the client whose key is sent.</param>
    /// <param name="publicKeyBase64">Base64‐encoded public key.</param>
    /// <param name="requesterId">UID of the client receiving the key.</param>
    public static void RelayPublicKeyToUser(Guid responderId, string publicKeyBase64,
        Guid requesterId)
    {
        List<Client> lstConnectedUsersSnapshot;
        lock (Users) lstConnectedUsersSnapshot = Users.ToList();

        var recipient = lstConnectedUsersSnapshot.FirstOrDefault(u => u.UID == requesterId);
        if (recipient == null || !recipient.ClientSocket.Connected)
        {
            ServerLogger.Log($"BroadcastPublicKeyToUser: recipient {requesterId} unavailable",
                ServerLogLevel.Warn);
            return;
        }

        var packetPublicKey = new PacketBuilder();
        packetPublicKey.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);

        // Appends the responder’s UID to indicate the origin of the public key
        packetPublicKey.WriteUid(responderId);

        // Appends the Base64‐encoded public key (or an empty string if null)
        packetPublicKey.WriteString(publicKeyBase64 ?? string.Empty);

        // Appends the requester’s UID to ensure the response is routed correctly
        packetPublicKey.WriteUid(requesterId);

        // Frames the assembled packet with a length prefix for network transmission
        byte[] framedPacket = Frame(packetPublicKey.GetPacketBytes());

        try
        {
            // Retrieves the recipient’s network stream from its TCP socket
            var netStream = recipient.ClientSocket.GetStream();

            // Writes the framed packet to the network stream
            netStream.Write(framedPacket, 0, framedPacket.Length);

            // Flushes the stream to guarantee immediate delivery
            netStream.Flush();

            ServerLogger.Log($"Sent public key of {responderId} to requester {requesterId}",
                ServerLogLevel.Debug);
        }
        catch (Exception ex)
        {
            ServerLogger.Log($"BroadcastPublicKeyToUser error: {ex.Message}",
                ServerLogLevel.Error
            );
        }
    }

    /// <summary>
    /// Signals each connected client that the server is shutting down,
    /// closes client connections gracefully, and logs the shutdown lifecycle.
    /// </summary>
    public static void Shutdown()
    {
        // Logs the initiation of the shutdown sequence
        ServerLogger.LogLocalized("ShutdownStart", ServerLogLevel.Info);

        // Takes a thread-safe snapshot of all connected clients
        List<Client> lstConnectedClientsSnapshot;
        lock (Users)
            lstConnectedClientsSnapshot = Users.ToList();

        // Iterates through each client to send a disconnect notification
        foreach (var client in lstConnectedClientsSnapshot)
        {
            try
            {
                // Builds a DisconnectClient packet with the server’s system UID and a standard message
                var packetBuilder = new PacketBuilder();
                packetBuilder.WriteOpCode((byte)ServerPacketOpCode.DisconnectClient);
                packetBuilder.WriteUid(SystemUID);
               
                // Frames the packet for network transport
                byte[] framedPacket = Frame(packetBuilder.GetPacketBytes());

                // Writes the framed packet to the client’s network stream if still connected
                if (client.ClientSocket.Connected)
                    client.ClientSocket.GetStream().Write(framedPacket, 0, framedPacket.Length);
            }
            catch (Exception ex)
            {
                // Logs any failure to notify an individual client
                ServerLogger.Log(
                    $"Shutdown notification failed for {client.Username} ({client.UID}): {ex.Message}",
                    ServerLogLevel.Error
                );
            }
        }

        // Logs the completion of the shutdown sequence
        ServerLogger.LogLocalized("ShutdownComplete", ServerLogLevel.Info);
    }

    /// <summary>
    /// Starts the TCP listener and runs the client-accept loop in a background task.
    /// </summary>
    public static void StartServerListener(int port)
    {
        _listener.Start();
        Console.WriteLine();
        ServerLogger.LogLocalized("ServerStartedOnPort", ServerLogLevel.Info, port);

        Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    TcpClient tcpClient = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    HandleNewClient(tcpClient);
                }
                catch (Exception ex)
                {
                    ServerLogger.Log($"Accept loop failure: {ex.Message}", ServerLogLevel.Error);
                }
            }
        });
    }
}



