/// <file>ClientConnection.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 31th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.Net.IO;
using chat_client.Properties;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Windows;

namespace chat_client.Net
{
    /// <summary>
    /// Represents the client-side connection to the server.
    /// Manages packet construction, reading, and dispatching.
    /// </summary>
    public class ClientConnection
    {
        /// <summary>Used to build outgoing packets. Never null.</summary>
        public PacketBuilder packetBuilder { get; } = new PacketBuilder();

        /// <summary>Provides the PacketReader used to read incoming packets; 
        /// initialized after connecting to the server.</summary>
        public PacketReader packetReader { get; private set; } = null!;

        /// <summary>Indicates whether the client is currently connected to the server.</summary>
        public bool IsConnected => _tcpClient?.Connected ?? false;

        // PUBLIC EVENTS

        // Fired when a new connection is about to start reading packets.
        // Subscribers should reset their roster snapshot state.
        public event Action? ConnectionEstablished;

        // Fired when the connection is being terminated.
        // Subscribers should reset their roster snapshot state.
        public event Action? ConnectionTerminated;

        // A new user joined (opcode 1)
        //   Parameters: uid, username, publicKey
        public event Action<Guid, string, byte[]>? UserConnectedEvent;

        // A plain-text message arrived (opcode 5)
        //   Parameter: the fully formatted text
        public event Action<string, string>? PlainMessageReceivedEvent;

        /// Raised when the server delivers an encrypted message (opcode 11).
        /// Parameters: sender GUID and raw ciphertext bytes
        public event Action<Guid, byte[]>? EncryptedMessageReceivedEvent;

        // A peer’s public key arrived (opcode 6)
        //   Parameters: senderUid, publicKeyDer
        public event Action<Guid, byte[]>? PublicKeyReceivedEvent;
   
        // A user disconnected (opcode 10)
        //   Parameters: uid, username
        public event Action<Guid, string>? UserDisconnectedEvent;

        // Server-initiated disconnect (opcode 12)
        //   No parameters
        public event Action? DisconnectedByServerEvent;

        /// <summary>Gets the UID assigned to the local user.</summary>
        public Guid LocalUid { get; private set; }

        /// <summary>Gets the public key assigned to the local user.</summary>
        public byte[] LocalPublicKey { get; private set; }

        /// <summary>
        /// Counts consecutive unknown opcodes seen in ReadPackets; resets when a valid opcode is processed.
        /// Used to close the connection if too many unexpected opcodes arrive in a row.
        /// </summary>
        private int _consecutiveUnexpectedOpcodes = 0;

        /// <summary>
        /// Atomic guard to ensure DisconnectFromServer logic runs once.
        /// 0 = not called, 1 = called.
        /// </summary>
        private int _disconnectFromServerCalled = 0;

        // Represents the handshake lifecycle; completed with true on success, false or exception on failure.
        // Recreate (or set to null) after completion to avoid accidental reuse.
        private TaskCompletionSource<bool>? _handshakeCompletionTcs;

        private TcpClient _tcpClient;

        /// <summary>
        /// Instantiates a new Server.
        /// Creates a fresh TcpClient, resets the local UID to Guid.Empty,
        /// and initializes the local public key to an empty byte array.
        /// </summary>
        public ClientConnection()
        {
            _tcpClient = new TcpClient();

            LocalUid = Guid.Empty;
            LocalPublicKey = Array.Empty<byte>();
        }

        /// <summary>
        /// • Validates and resolves the target IP address and port.
        /// • Disposes any previous socket and provides a fresh TcpClient placeholder.
        /// • Connects the TcpClient to the remote server endpoint.
        /// • Constructs a PacketReader over the active network stream for framed parsing.
        /// • Generates a unique session identity (GUID) and retrieves the local public key (DER).
        /// • Sends a framed handshake packet containing username, UID and public key to the server.
        /// • On successful handshake, invokes connection-established callbacks and starts the background packet reader.
        /// • On failure, performs cleanup and returns an empty result.
        /// </summary>
        /// <param name="username">Display name to present to the server.</param>
        /// <param name="ipAddressOfServer">Server IP or hostname. If null/empty defaults to 127.0.0.1.</param>
        /// <param name="cancellationToken">Cancellation token used for connect/handshake operations.</param>
        /// <returns>Tuple of (uid, publicKeyDer) when success; empty values on failure.</returns>
        public async Task<(Guid uid, byte[] publicKeyDer)> ConnectToServerAsync(
            string username,
            string ipAddressOfServer,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Defensive dispose of any previous client to ensure a fresh start.
                try { _tcpClient?.Close(); } catch { }
                try { _tcpClient?.Dispose(); } catch { }

                _tcpClient = new TcpClient();

                // Choose target IP, defaulting to loopback for convenience in local dev.
                string ipToConnect = string.IsNullOrWhiteSpace(ipAddressOfServer) ? "127.0.0.1" : ipAddressOfServer;

                // Validates the IP string when it's not the explicit local default.
                if (ipToConnect != "127.0.0.1" && !System.Net.IPAddress.TryParse(ipToConnect, out _))
                {
                    throw new ArgumentException(LocalizationManager.GetString("IPAddressInvalid"));
                }

                // Selects port from settings or fallback to the well-known default.
                int port = Properties.Settings.Default.UseCustomPort ? Properties.Settings.Default.CustomPortNumber : 7123;

                // Establishes TCP connection asynchronously.
                await _tcpClient.ConnectAsync(ipToConnect, port).ConfigureAwait(false);
                ClientLogger.Log($"TCP connection established — IP: {ipToConnect}, Port: {port}", ClientLogLevel.Debug);

                // Builds the packet reader over the network stream. PacketReader is async-first.
                packetReader = new PacketReader(_tcpClient.GetStream());

                // Generates a new session identity and load the local public key bytes.
                Guid uid = Guid.NewGuid();
                byte[] publicKeyDer = EncryptionHelper.PublicKeyDer ?? Array.Empty<byte>();

                // Persists locally for other components to reference.
                LocalUid = uid;
                LocalPublicKey = publicKeyDer;

                // Notifies listeners that a low-level connection has been established.
                ConnectionEstablished?.Invoke();

                // Sends the initial handshake packet to the server.
                bool handshakeSent = await SendInitialConnectionPacketAsync(username, uid, publicKeyDer, cancellationToken).ConfigureAwait(false);
                if (!handshakeSent)
                {
                    ClientLogger.LogLocalized(LocalizationManager.GetString("ErrorFailedToSendInitialHandshake"), ClientLogLevel.Error);

                    try 
                    {
                        _tcpClient?.Close(); 
                    } 
                    catch 
                    { 
                    }

                    try
                    { 
                        _tcpClient?.Dispose(); 
                    } 
                    catch 
                    { 
                    }

                    _tcpClient = new TcpClient();
                    packetReader = new PacketReader(Stream.Null);

                    return (Guid.Empty, Array.Empty<byte>());
                }

                // Waits for an explicit HandshakeAck from the server before starting the read loop.
                // This prevents the client from consuming messages before the server accepted the session.
                using (var ackCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    ackCts.CancelAfter(TimeSpan.FromSeconds(5)); // tunable handshake ack timeout
                    try
                    {
                        // Reads one framed body (4B length + payload) using the async packetReader helper
                        // packetReader was created earlier over the same NetworkStream
                        byte[] ackFrame = await packetReader.ReadFramedBodyAsync(ackCts.Token).ConfigureAwait(false);

                        if (ackFrame == null || ackFrame.Length == 0)
                            throw new InvalidDataException("Empty handshake ack frame");

                        using var ackMs = new MemoryStream(ackFrame);
                        var ackReader = new PacketReader(ackMs);

                        // Reads the opcode byte asynchronously using the handshake-specific cancellation token.
                        var ackOpcodeByte = await ackReader.ReadByteAsync(ackCts.Token).ConfigureAwait(false);
                        var ackOpcode = (ClientPacketOpCode)ackOpcodeByte;

                        if (ackOpcode != ClientPacketOpCode.HandshakeAck)
                        {
                            ClientLogger.Log($"Handshake failed: unexpected opcode {(byte)ackOpcode}", ClientLogLevel.Error);

                            try 
                            { 
                                _tcpClient?.Close();
                            } 
                            catch
                            { 
                            }
                            
                            try 
                            { 
                                _tcpClient?.Dispose(); 
                            } 
                            catch 
                            { 
                            }

                            _tcpClient = new TcpClient();
                            packetReader = new PacketReader(Stream.Null);

                            return (Guid.Empty, Array.Empty<byte>());
                        }

                        /// <summary>
                        /// Launches the packet reader on a background thread to handle
                        /// incoming messages without blocking the caller.
                        /// </summary>
                        _ = Task.Run(() => ReadPacketsAsync(cancellationToken), cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        ClientLogger.Log("Handshake ack not received within timeout", ClientLogLevel.Error);

                        try { _tcpClient?.Close(); } catch { }
                        try { _tcpClient?.Dispose(); } catch { }

                        _tcpClient = new TcpClient();
                        packetReader = new PacketReader(Stream.Null);

                        return (Guid.Empty, Array.Empty<byte>());
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"Error while waiting for handshake ack: {ex.Message}", ClientLogLevel.Error);

                        try { _tcpClient?.Close(); } catch { }
                        try { _tcpClient?.Dispose(); } catch { }

                        _tcpClient = new TcpClient();
                        packetReader = new PacketReader(Stream.Null);

                        return (Guid.Empty, Array.Empty<byte>());
                    }
                }

                return (uid, publicKeyDer);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"[ERROR] ConnectToServerAsync failed: {ex.Message}", ClientLogLevel.Error);

                try 
                {
                    _tcpClient?.Close(); 
                } 
                catch 
                { 
                
                }
                
                try 
                { 
                    _tcpClient?.Dispose(); 
                } 
                catch
                { 
                
                }

                // Ensures safe placeholders so callers never observe null references.
                _tcpClient = new TcpClient();
                packetReader = new PacketReader(Stream.Null);

                return (Guid.Empty, Array.Empty<byte>());
            }
        }

        /// <summary>
        /// • Performs deterministic cleanup of network resources and session state.
        /// • Closes and disposes the active network stream and TcpClient if present.
        /// • Replaces disposed network objects with safe, not-connected placeholders to preserve non-null invariants.
        /// • Resets per-connection counters, so future Connect attempts are valid.
        /// • Notifies listeners/UI that the connection has terminated.
        /// </summary>
        public void DisconnectFromServer()
        {
            /// <summary>
            /// Ensures the close logic runs only once concurrently.
            /// Uses Interlocked.Exchange to atomically set a guard flag and detect re-entrancy
            /// so simultaneous calls from different threads do not execute cleanup multiple times.
            /// </summary>
            if (Interlocked.Exchange(ref _disconnectFromServerCalled, 1) != 0)
                return;

            try
            {
                // Attempts to close the network stream safely.
                try
                {
                    var networkStream = _tcpClient?.GetStream();
                    try
                    { 
                        networkStream?.Close();
                    } 
                    catch (Exception ex) 
                    { 
                        ClientLogger.Log($"NetworkStream close failed: {ex.Message}", ClientLogLevel.Warn); 
                    }
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"NetworkStream access failed: {ex.Message}", ClientLogLevel.Warn);
                }

                // Attempts to close and dispose the existing TcpClient.
                try
                {
                    try
                    { 
                        _tcpClient?.Close();
                    } 
                    catch (Exception ex) 
                    { 
                        ClientLogger.Log($"TcpClient close failed: {ex.Message}", ClientLogLevel.Warn); 
                    }

                    try 
                    { 
                        _tcpClient?.Dispose();
                    } 
                    catch (Exception ex) 
                    { 
                        ClientLogger.Log($"TcpClient dispose failed: {ex.Message}", ClientLogLevel.Warn); 
                    }
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"TcpClient cleanup failed: {ex.Message}", ClientLogLevel.Warn);
                }

                // Replaces disposed objects with safe placeholders to avoid nullable warnings and accidental reuse.
                try
                {
                    _tcpClient = new TcpClient();
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"TcpClient placeholder creation failed: {ex.Message}", ClientLogLevel.Warn);
                }

                try
                {
                    // PacketReader over Stream.Null provides a harmless, readable no-op stream.
                    packetReader = new PacketReader(Stream.Null);
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"PacketReader placeholder creation failed: {ex.Message}", ClientLogLevel.Warn);
                }

                // Resets runtime counter to a known baseline.
                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                // Notifies UI/listeners that the connection has terminated.
                ConnectionTerminated?.Invoke();
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Disconnect failed during cleanup: {ex.Message}", ClientLogLevel.Error);
            }
            finally
            {
                // Allows future disconnect attempts to run if necessary by resetting the guard.
                Volatile.Write(ref _disconnectFromServerCalled, 0);
            }
        }

        /// <summary> 
        /// Returns all known public RSA keys for connected users. 
        /// Filters out users with empty UID or missing public key bytes 
        /// and returns a Dictionary keyed by Guid with DER byte[] values. 
        /// A Dictionary is a collection of key/value pairs that allows 
        /// fast lookup of a value by its unique key; here the key is the
        /// user’s Guid and the value is the user’s public key in DER format.
        /// Using a Dictionary makes it efficient to find a specific user’s
        /// public key when encrypting a message or verifying signatures.
        /// </summary>

        public static Dictionary<Guid, byte[]> GetAllKnownPublicKeys(MainViewModel viewModel)
        {
            // Returns an empty dictionary if viewModel or Users list is null
            if (viewModel?.Users == null)
                return new Dictionary<Guid, byte[]>();

            return viewModel.Users
                // Uses lambdas functions : short parameter names like usr are generic.
                // This filters out users with uninitialized UID or empty public key.
                .Where(usr => usr.UID != Guid.Empty && usr.PublicKeyDer != null && usr.PublicKeyDer.Length > 0)
                // Project to Guid -> byte[] dictionary
                .ToDictionary(usr => usr.UID, usr => usr.PublicKeyDer!);
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
        /// Marks the client-side handshake as complete so the UI/logic can safely proceed.
        /// Completes the handshake TaskCompletionSource with success (true) in a race-safe manner.
        /// If the TCS is not initialized, this method creates one already completed to keep behavior stable.
        /// </summary>
        public void MarkHandshakeComplete()
        {
            // Ensures Task Completion Source exists and use RunContinuationsAsynchronously to avoid running
            // continuations on the thread that completes the TCS.
            var tcs = _handshakeCompletionTcs;
            if (tcs == null)
            {
                // Creates an already-completed TCS to preserve callers that check Task.IsCompleted.
                _handshakeCompletionTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                _handshakeCompletionTcs.TrySetResult(true);
                return;
            }

            // Completes successfully if not already completed (TrySetResult is idempotent and race-safe).
            tcs.TrySetResult(true);
        }

        /// <summary>
        /// Runs on a background thread to read all incoming framed packets
        /// until the connection closes.
        /// • Reads full framed payloads (length-prefixed) and parses each field using the
        ///   async PacketReader.
        /// • Applies roster snapshots on the UI thread to avoid transient inconsistencies.
        /// • Completes the handshake TaskCompletionSource when a HandshakeAck is received.
        /// • Detects repeated unexpected opcodes and triggers a graceful disconnect when a
        /// threshold is reached.
        /// • Uses ConfigureAwait(false) for I/O awaits and explicitly dispatches UI updates
        ///   via the application dispatcher.
        /// • Stops on stream close, protocol error, or cancellation.
        /// </summary>

        private async Task ReadPacketsAsync(CancellationToken cancellationToken)
        {
            // Captures ViewModel reference on the UI thread so the reader can dispatch updates.
            MainViewModel viewModel = null!;

            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mw)
                    viewModel = mw.ViewModel;
            });

            if (viewModel == null)
                return;

            // Loops continuously until cancellation is requested.
            // This guards the read lifecycle and allows graceful shutdown via a CancellationToken.
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Reads a single framed body
                    byte[] framedBody = await packetReader.ReadFramedBodyAsync(cancellationToken).ConfigureAwait(false);

                    if (framedBody == null || framedBody.Length == 0)
                        throw new InvalidDataException("Empty framed body received from server.");

                    // Parses the frame using an in-memory PacketReader instance.
                    using var ms = new MemoryStream(framedBody, writable: false);
                    var reader = new PacketReader(ms);

                    // Opcode is the first byte of the framed payload.
                    byte opcodeByte = await reader.ReadByteAsync(cancellationToken).ConfigureAwait(false);
                    var opcode = (ClientPacketOpCode)opcodeByte;

                    switch (opcode)
                    {
                        case ClientPacketOpCode.RosterBroadcast:
                            
                            // Resets consecutive unexpected-opcode counter on valid packet processing.
                            if (_consecutiveUnexpectedOpcodes != 0)
                            {
                                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);
                            }

                            // totalUsers is sent as a 32-bit network-order int.
                            int totalUsers = await reader.ReadInt32NetworkOrderAsync(cancellationToken).ConfigureAwait(false);

                            var rosterEntries = new List<(Guid UserId, string Username, byte[] PublicKeyDer)>();
                            for (int i = 0; i < totalUsers; i++)
                            {
                                // Reads the 16-byte user identifier (UID) from the packet.
                                Guid userId = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                // Reads the length-prefixed UTF-8 username string.
                                string username = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                // Reads the length-prefixed DER public key bytes (capped at 64 KiB).
                                byte[] publicKeyDer = await reader.ReadBytesWithLengthAsync(maxAllowed: 64 * 1024, cancellationToken).ConfigureAwait(false);

                                rosterEntries.Add((userId, username, publicKeyDer));
                            }

                            // Applies roster snapshot on the UI thread to avoid transient inconsistencies.
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                viewModel.DisplayRosterSnapshot(rosterEntries);
                            });
                            break;

                        case ClientPacketOpCode.HandshakeAck:
                            
                            // Ensures the handshake completion TCS is observed/completed exactly once.
                            _handshakeCompletionTcs?.TrySetResult(true);
                            Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);
                            break;

                        case ClientPacketOpCode.PlainMessage:
                            
                            // Resets unexpected-opcode counter.
                            Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                            // Plain-text message payload:
                            //   [16-byte sender UID]
                            //   [16-byte recipient UID placeholder]
                            //   [length-prefixed UTF-8 text]
                            Guid senderUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                            // Discards recipient UID placeholder to preserve alignment.
                            _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                            string message = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                            string senderName = viewModel.Users
                                .FirstOrDefault(u => u.UID == senderUid)?.Username
                                ?? senderUid.ToString();

                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnPlainMessageReceived(senderName, message));
                            break;

                        case ClientPacketOpCode.EncryptedMessage:
                            // Resets unexpected-opcode counter.
                            Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                            // Reads the 16-byte sender UID from the packet.
                            Guid encSenderUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                            // Reads and discard the 16-byte recipient UID to maintain stream alignment.
                            _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                            // Reads the length-prefixed ciphertext bytes (no explicit max).
                            byte[] cipherBytes = await reader.ReadBytesWithLengthAsync(maxAllowed: null, cancellationToken).ConfigureAwait(false);

                            // Resolves the sender's display name or fall back to the sender UID string.
                            string encSenderName = viewModel.Users
                                .FirstOrDefault(u => u.UID == encSenderUid)?.Username
                                ?? encSenderUid.ToString();

                            // Decrypts using the byte[] overload (synchronous decryption kept local).
                            string plainText = EncryptionHelper.DecryptMessageFromBytes(cipherBytes);

                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnPlainMessageReceived(encSenderName, plainText));
                            break;

                        case ClientPacketOpCode.PublicKeyResponse:
                            
                            // Resets unexpected-opcode counter.
                            Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                            // Reads the 16-byte origin UID for which the public key is being returned.
                            Guid originUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                            // Reads the length-prefixed DER-encoded public key bytes (no explicit max).
                            byte[] keyDer = await reader.ReadBytesWithLengthAsync(maxAllowed: null, cancellationToken).ConfigureAwait(false);

                            // Reads and discard the 16-byte requester UID to preserve stream alignment.
                            _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnPublicKeyReceived(originUid, keyDer));
                            break;

                        case ClientPacketOpCode.DisconnectNotify:
                            Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                            // DisconnectNotify:
                            //   [16-byte UID][length-prefixed username]
                            Guid discUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                            string discName = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnUserDisconnected(discUid, discName));
                            break;

                        case ClientPacketOpCode.ForceDisconnectClient:
                            // Server requested immediate disconnect; notify UI and exit.
                            Application.Current.Dispatcher.Invoke(() =>
                                viewModel.OnDisconnectedByServer());
                            return;

                        default:
                            {
                                // Unexpected opcode handling: increment counter and possibly disconnect.
                                ClientLogger.Log($"Unexpected opcode 0x{opcodeByte:X2} in framed packet", ClientLogLevel.Warn);

                                if (Interlocked.Increment(ref _consecutiveUnexpectedOpcodes) >= 3)
                                {
                                    ClientLogger.Log("Too many consecutive unexpected opcodes, initiating graceful disconnect.", ClientLogLevel.Warn);
                                    Application.Current.Dispatcher.Invoke(() =>
                                        viewModel.OnDisconnectedByServer());
                                    return;
                                }

                                break;
                            }
                    }
                }
                catch (EndOfStreamException)
                {
                    ClientLogger.Log("ReadPackets: remote closed stream", ClientLogLevel.Debug);
                }
                catch (IOException ioe)
                {
                    ClientLogger.Log($"ReadPackets IO: {ioe.Message}", ClientLogLevel.Debug);
                }
                catch (InvalidDataException ide)
                {
                    ClientLogger.Log($"ReadPackets protocol error: {ide.Message}", ClientLogLevel.Warn);
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"ReadPackets error: {ex.Message}", ClientLogLevel.Error);
                }
                finally
                {
                    // Centralized cleanup after any exception or normal exit.
                    try
                    {
                        // Notifies UI on the dispatcher thread that the server disconnected.
                        Application.Current.Dispatcher.Invoke(() => viewModel.OnDisconnectedByServer());
                    }
                    catch { }

                    try
                    {
                        _tcpClient?.Close();
                    }
                    catch
                    {
                    }

                    try
                    {
                        _tcpClient?.Dispose();
                    }
                    catch
                    {
                    }

                    // Creates safe, non-null placeholders to satisfy nullable analysis and
                    // avoid accidental reuse of a disposed instance.
                    // A freshly constructed TcpClient is in the "not connected" state and
                    // will be explicitly connected by ConnectToServer().
                    _tcpClient = new TcpClient();

                    // Provides a harmless reader over Stream.Null so code that reads the
                    // variable never gets a null reference. This avoids nullable warnings.
                    packetReader = new PacketReader(Stream.Null);

                    // Resets runtime counter
                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);
                }

                // Exits the reader loop
                return;
            }
        }

        /// <summary>
        /// Sends a PublicKeyRequest packet to the server to retrieve all known public keys.
        /// Writes the PublicKeyRequest opcode followed by this client’s UID,
        /// flushes the stream to guarantee delivery,
        /// and logs the action for traceability.
        /// </summary>
        public void SendRequestAllPublicKeysFromServer()
        {
            // Builds the request packet: opcode + sender UID
            var packetBuilder = new PacketBuilder();
            packetBuilder.WriteOpCode((byte)ClientPacketOpCode.PublicKeyRequest);
            packetBuilder.WriteUid(LocalUid);

            // Sends the packet over the network stream and flushes immediately
            NetworkStream stream = _tcpClient.GetStream();
            byte[] payload = packetBuilder.GetPacketBytes();
            stream.Write(payload, 0, payload.Length);
            stream.Flush();

            // Logs the sync request with this client's UID
            ClientLogger.Log($"Public key sync request sent — UID: {LocalUid}",
                ClientLogLevel.Debug);
        }

        /// <summary>
        /// Sends a framed DisconnectNotify packet to the server
        /// to announce a clean disconnect.
        /// Packet layout:
        ///   [4-byte big-endian length prefix]
        ///   [1-byte opcode: DisconnectNotify]
        ///   [16-byte UID of the disconnecting client]
        /// </summary>
        public void SendDisconnectNotifyToServer()
        {
            try
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ClientPacketOpCode.DisconnectNotify);
                builder.WriteUid(LocalUid);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                _tcpClient.Client.Send(framedPacket);
                ClientLogger.Log($"Sent DisconnectNotify for {LocalUid}", ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"DisconnectNotify failed: {ex.Message}", ClientLogLevel.Warn);
            }
        }

        public Task<bool> SendEncryptedMessageToServerAsync(string plainText)
        {
            // Sanity checks kept on caller thread
            if (string.IsNullOrWhiteSpace(plainText))
                return Task.FromResult(false);

            if (Application.Current.MainWindow is not MainWindow mainWindow ||
                mainWindow.ViewModel is not MainViewModel viewModel ||
                viewModel.LocalUser == null)
            {
                return Task.FromResult(false);
            }

            // Offloads the heavy work to the thread pool to avoid blocking UI
            return Task.Run(() =>
            {
                Guid senderUid = viewModel.LocalUser.UID;
                var recipients = viewModel.Users.Where(u => u.UID != senderUid).ToList();
                if (recipients.Count == 0)
                    recipients.Add(viewModel.LocalUser);

                bool messageSent = false;

                foreach (var recipient in recipients)
                {
                    Guid recipientUid = recipient.UID;
                    byte[] publicKeyDer;

                    // Obtain public key with minimal locking
                    lock (viewModel.KnownPublicKeys)
                    {
                        if (recipientUid == senderUid)
                        {
                            publicKeyDer = viewModel.LocalUser.PublicKeyDer ?? Array.Empty<byte>();
                        }
                        else
                        {
                            viewModel.KnownPublicKeys.TryGetValue(recipientUid, out byte[]? key);
                            publicKeyDer = key ?? Array.Empty<byte>();
                        }
                    }

                    if (recipientUid == senderUid)
                    {
                        if (publicKeyDer.Length == 0)
                        {
                            ClientLogger.Log($"Cannot encrypt to self: missing local public key for UID {senderUid}", ClientLogLevel.Error);
                            continue;
                        }
                    }
                    else
                    {
                        if (publicKeyDer.Length == 0)
                        {
                            // Request peer key (fire-and-forget; keeps UI flow non-blocking)
                            SendRequestToPeerForPublicKey(recipientUid);
                            continue;
                        }

                        // Ensure server has our public key; keep this sync call but it's off the UI thread now
                        var localKey = viewModel.LocalUser.PublicKeyDer ?? Array.Empty<byte>();
                        if (localKey.Length == 0)
                        {
                            ClientLogger.Log("Cannot send public key: LocalUser.PublicKeyDer is uninitialized.", ClientLogLevel.Warn);
                        }
                        else
                        {
                            viewModel._server.SendPublicKeyToServer(viewModel.LocalUser.UID, localKey);
                        }

                        viewModel.MarkKeyAsSentTo(recipientUid);
                    }

                    try
                    {
                        byte[] cipherArray = EncryptionHelper.EncryptMessageToBytes(plainText, publicKeyDer);
                        if (cipherArray == null || cipherArray.Length == 0)
                        {
                            ClientLogger.Log($"Encryption produced empty ciphertext for recipient {recipientUid}.", ClientLogLevel.Warn);
                            continue;
                        }

                        var encryptedMessagePacket = new PacketBuilder();
                        encryptedMessagePacket.WriteOpCode((byte)ClientPacketOpCode.EncryptedMessage);
                        encryptedMessagePacket.WriteUid(senderUid);
                        encryptedMessagePacket.WriteUid(recipientUid);
                        encryptedMessagePacket.WriteBytesWithLength(cipherArray);

                        _tcpClient.Client.Send(encryptedMessagePacket.GetPacketBytes());
                        ClientLogger.Log($"Encrypted message sent to {recipientUid}.", ClientLogLevel.Debug);

                        messageSent = true;
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"Failed to encrypt or send to {recipientUid}: {ex.Message}", ClientLogLevel.Error);
                    }
                }

                return messageSent;
            });
        }


        /// <summary>
        /// Builds and sends a framed handshake packet (opcode = Handshake) to the server asynchronously.
        /// Packet format on the wire:
        ///   [4-byte big-endian length][1-byte opcode][username (length-prefixed UTF-8)]
        ///   [16-byte UID][4-byte publicKeyDer length][publicKeyDer bytes]
        /// This method only sends the handshake; it does NOT start the read loop. Caller is responsible
        /// for starting the inbound reader after verifying the server handshake ack.
        /// </summary>
        /// <param name="username">The display name of the user.</param>
        /// <param name="uid">The unique identifier assigned to the client during connection.</param>
        /// <param name="publicKeyDer">The DER-encoded RSA public key bytes.</param>
        /// <param name="cancellationToken">Cancellation token for the send operation.</param>
        /// <returns>True if the handshake packet was sent; false on error or invalid state.</returns>
        public async Task<bool> SendInitialConnectionPacketAsync(
            string username,
            Guid uid,
            byte[] publicKeyDer,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            if (_tcpClient == null || _tcpClient?.Connected != true)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync failed: socket not connected.", ClientLogLevel.Error);
                return false;
            }

            if (uid == Guid.Empty)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync failed: UID is empty.", ClientLogLevel.Error);
                return false;
            }

            if (publicKeyDer == null)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync failed: publicKeyDer is null.", ClientLogLevel.Error);
                return false;
            }

            try
            {
                // Builds the payload using PacketBuilder: opcode + username + uid + length-prefixed public key
                var packetBuilder = new PacketBuilder();
                packetBuilder.WriteOpCode((byte)ClientPacketOpCode.Handshake);
                packetBuilder.WriteString(username);
                packetBuilder.WriteUid(uid);
                packetBuilder.WriteBytesWithLength(publicKeyDer);

                // Obtains raw payload bytes and frames them with the 4-byte big-endian length prefix.
                byte[] payload = packetBuilder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                // Sends framed bytes via the NetworkStream using async APIs.
                NetworkStream networkStream = _tcpClient.GetStream();

                await networkStream.WriteAsync(framedPacket, 0, framedPacket.Length, cancellationToken).ConfigureAwait(false);
                await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);

                return true;
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync cancelled by token.", ClientLogLevel.Debug);
                return false;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"SendInitialConnectionPacketAsync exception: {ex.Message}", ClientLogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// Builds and sends a framed plain-text chat packet to the server asynchronously.
        /// Packet structure:
        ///   [4-byte big-endian length]
        ///   [1-byte opcode: PlainMessage]
        ///   [16-byte sender UID]
        ///   [4-byte message length][UTF-8 message bytes]
        /// Sends the framed packet atomically.
        /// </summary>
        /// <param name="message">The chat message to broadcast.</param>
        /// <returns>True if the packet was sent; false on error or invalid state.</returns>
        public async Task<bool> SendPlainMessageToServerAsync(string message)
        {
            // Validates input message early to avoid unnecessary allocations or network activity.
            if (string.IsNullOrWhiteSpace(message))
                return false;

            // Ensures the TCP client and underlying socket are valid and connected.
            if (_tcpClient?.Connected != true)
            {
                ClientLogger.Log("SendPlainMessageToServer failed: socket not connected.", ClientLogLevel.Error);
                return false;
            }

            // Retrieves application UI model and verifies that the local user is initialized.
            if (Application.Current.MainWindow is not MainWindow mainWindow ||
                mainWindow.ViewModel is not MainViewModel viewModel ||
                viewModel.LocalUser == null)
            {
                ClientLogger.Log("SendPlainMessageToServer failed: Local user is not initialized.", ClientLogLevel.Error);
                return false;
            }

            // Validates that the local user's GUID is set.
            Guid senderUid = viewModel.LocalUser.UID;
            if (senderUid == Guid.Empty)
            {
                ClientLogger.Log("SendPlainMessageToServer failed: LocalUser.UID is empty.", ClientLogLevel.Error);
                return false;
            }

            // Trims and normalizes the message to avoid sending leading/trailing whitespace.
            string trimmedMessage = message.Trim();
            if (trimmedMessage.Length == 0)
            {
                return false;
            }

            try
            {
                // Builds the packet payload using PacketBuilder.
                // The payload contains: opcode, sender UID, and the UTF-8 length-prefixed message.
                var packetBuilder = new PacketBuilder();
                packetBuilder.WriteOpCode((byte)ClientPacketOpCode.PlainMessage);
                packetBuilder.WriteUid(senderUid);
                packetBuilder.WriteString(trimmedMessage);

                // Acquires the NetworkStream from the TcpClient used for this connection.
                NetworkStream networkStream = _tcpClient.GetStream();

                // Sends the framed packet atomically via the network stream.
                await packetBuilder.WriteFramedPacketAsync(networkStream).ConfigureAwait(false);

                // Creates a short preview for logging to avoid leaking long messages into logs.
                string logPreview = trimmedMessage.Length > 64
                    ? trimmedMessage.Substring(0, 64) + "…"
                    : trimmedMessage;

                ClientLogger.Log($"Sending plain message: \"{logPreview}\"", ClientLogLevel.Debug);
                return true;
            }
            catch (Exception ex)
            {
                // Logs and returns false on any network or builder error.
                ClientLogger.Log($"SendPlainMessageToServer exception: {ex.Message}", ClientLogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// • Sends the client's public RSA key to the server for distribution to other connected clients.
        /// • Builds a packet with OpCode 6, including the sender's UID and public key in DER byte-array format.
        /// • Validates socket connectivity before dispatching and logs each step for traceability.
        /// • Allows transmission even if handshake is not completed to support single-client scenarios.
        /// • Returns true if the packet was sent successfully; false otherwise.
        /// </summary>
        /// <param name="targetUid">The UID of the sender.</param>
        /// <param name="publicKeyDer">The public RSA key as DER bytes (PKCS#1 RSAPublicKey).</param>
        /// <returns>True if the packet was sent successfully; false if the client is not connected.</returns>
        public bool SendPublicKeyToServer(Guid targetUid, byte[] publicKeyDer)
        {
            // Validates socket connection before attempting to send
            if (_tcpClient?.Client == null || !_tcpClient.Connected)
            {
                ClientLogger.Log("Cannot send public key — client is not connected.", ClientLogLevel.Error);
                return false;
            }

            // Builds the packet with required fields
            var publicKeyPacket = new PacketBuilder();
            publicKeyPacket.WriteOpCode((byte)ClientPacketOpCode.PublicKeyResponse);
            publicKeyPacket.WriteUid(targetUid);
            publicKeyPacket.WriteBytesWithLength(publicKeyDer);

            ClientLogger.Log($"Sending public key — UID: {targetUid}, Key length: {publicKeyDer.Length}", ClientLogLevel.Debug);

            // Sends the packet to the server
            _tcpClient.Client.Send(publicKeyPacket.GetPacketBytes());

            ClientLogger.Log("Public key packet sent successfully.", ClientLogLevel.Debug);
            return true;
        }

        /// <summary>
        /// Builds and sends a PublicKeyRequest packet to the server.
        /// Packet structure:
        ///   [4-byte length prefix]
        ///   [1-byte opcode: PublicKeyRequest]
        ///   [16-byte requester UID]
        ///   [16-byte target UID]
        /// </summary>
        /// <param name="targetUid">UID of the peer whose key is requested.</param>
        public void SendRequestToPeerForPublicKey(Guid targetUid)
        {
            try
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ClientPacketOpCode.PublicKeyRequest);
                builder.WriteUid(LocalUid);
                builder.WriteUid(targetUid);

                byte[] payload = builder.GetPacketBytes();
                byte[] framedPacket = Frame(payload);

                _tcpClient.Client.Send(framedPacket);
                ClientLogger.Log($"Requested public key for {targetUid}.", ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Key request for {targetUid} failed: {ex.Message}", ClientLogLevel.Error);
            }
        }
    }
}
