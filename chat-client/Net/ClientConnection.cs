/// <file>ClientConnection.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 27th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.Net.IO;
using chat_client.Properties;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Policy;
using System.Text;
using System.Windows;

namespace chat_client.Net
{
    /// <summary>
    /// Represents the client-side connection to the server.
    /// Manages packet construction, reading, and dispatching.
    /// </summary>
    public class ClientConnection
    {
        /// <summary>
        /// CancellationTokenSource dedicated to the active connection lifecycle, 
        /// used to control and terminate the background packet reader.
        private CancellationTokenSource? _connectionCts;

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

        // Represents the handshake lifecycle; completed with true on success, false on failure/exception.
        private TaskCompletionSource<bool>? _handshakeCompletionTcs;

        /// <summary>
        /// Ensures that encryption initialization runs only once per session.
        /// Used as an interlocked flag: 0 = not initialized, 1 = already initialized.
        /// Reset to 0 during disconnect cleanup to allow fresh initialization.
        /// </summary>
        private int _encryptionInitOnce = 0;

        /// <summary>
        /// Indicates whether the local public key has already been sent to the server.
        /// • Ensures idempotence: the key is transmitted only once after HandshakeAck.
        /// • Prevents repeated key-send loops during reconnection or multiple ACK events.
        /// </summary>
        private bool _hasSentPublicKey = false;

        // Private backing PacketReader used internally (initialized in ConnectToServerAsync)
        private PacketReader? _packetReader;

        /// <summary>
        /// Provides the encryption pipeline used to publish keys, synchronize peers, and evaluate readiness.
        /// Must be injected at construction to avoid null references.
        /// </summary>
        private readonly EncryptionPipeline _encryptionPipeline;

        // Reader lock to serialize critical reads and avoid concurrent consumption of the NetworkStream.
        // This field may be reset by CleanConnection to guarantee a fresh, uncontended semaphore.
        private SemaphoreSlim _readerLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Callback used to run actions on the UI thread, ensuring safe property updates.
        /// </summary>
        private readonly Action<Action> _uiDispatcherInvoke;

        // Single-writer guard for this connection instance; kept readonly for the connection lifetime.
        private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);

        private TcpClient _tcpClient;

        // PUBLIC PROPERTIES

        /// <summary>Used to build outgoing packets. Never null.</summary>
        public PacketBuilder packetBuilder { get; } = new PacketBuilder();

        /// <summary>Indicates whether the client is currently connected to the server.</summary>
        public bool IsConnected => _tcpClient?.Connected ?? false;

        /// <summary>Indicates whether the TCP socket is connected and the handshake(HandshakeAck) 
        /// has been successfully confirmed</summary>
        public bool IsEstablished => IsConnected && _handshakeCompletionTcs != null 
            && _handshakeCompletionTcs.Task.IsCompletedSuccessfully && _handshakeCompletionTcs.Task.Result == true;

        /// <summary> Gets the UID assigned to the local user </summary>
        public Guid LocalUid { get; private set; }

        /// <summary>
        /// Gets or sets the local public key used for encryption.
        /// </summary>
        public byte[] LocalPublicKey { get; set; } = Array.Empty<byte>();

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

        /// <summary>
        /// Initializes a new ClientConnection instance.
        /// Sets up the underlying TCP client, resets local identifiers,
        /// and stores the UI dispatcher dependency provided by MainViewModel.
        /// </summary>
        public ClientConnection(Action<Action> uiDispatcherInvoke)
        {
            // Underlying TCP client used for communication
            _tcpClient = new TcpClient();

            // Reset local identifiers for a fresh session
            LocalUid = Guid.Empty;
            LocalPublicKey = Array.Empty<byte>();

            /// <summary> Stores the UI dispatcher callback passed from MainViewModel </summary>
            _uiDispatcherInvoke = uiDispatcherInvoke ?? throw new ArgumentNullException(nameof(uiDispatcherInvoke));
        }


        /// <summary>
        /// Cleanly resets the client connection state:
        /// • Cancels and disposes any pending handshake TaskCompletionSource to wake awaiters
        /// • Cancels and disposes the connection CancellationTokenSource to stop the background reader
        /// • Disposes the TcpClient (which also closes the NetworkStream) and reinitializes a fresh instance
        /// • Clears the PacketReader backing field (not IDisposable)
        /// • Disposes and recreates the reader lock to ensure a fresh semaphore
        /// • Resets handshake/encryption flags to ensure fresh state
        /// • UI update is delegated to the caller
        /// </summary>
        private void CleanConnection()
        {
            // Resets handshake/encryption flags
            _hasSentPublicKey = false;
            Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

            // Cancels handshake TCS to wake any awaiters
            _handshakeCompletionTcs?.TrySetCanceled();
            _handshakeCompletionTcs = null;

            // Cancels and disposes connection CTS to stop read loop
            _connectionCts?.Cancel();
            _connectionCts?.Dispose();
            _connectionCts = null;

            // Disposes TcpClient (closes stream) and reinitializes a fresh socket
            try
            {
                _tcpClient?.Dispose();
            }
            catch
            {
                
            }
            _tcpClient = new TcpClient();

            // Clears PacketReader reference (not IDisposable)
            _packetReader = null!;

            // Disposes and recreates the reader lock semaphore
            try
            {
                _readerLock?.Dispose();
            }
            catch
            {
                // Swallows disposal exceptions to keep shutdown resilient
            }
            _readerLock = new SemaphoreSlim(1, 1);

            // Delegates UI update to the caller

            ClientLogger.Log("Client connection cleaned up.", ClientLogLevel.Debug);
        }

        /// <summary>
        /// Validates IP/port, opens TCP, initializes reader/locks, generates UID, performs handshake,
        /// marks pipeline ready, and starts the background packet reader.
        /// </summary>
        /// <param name="username">Display name to present to the server.</param>
        /// <param name="ipAddressOfServer">Server IP or hostname. Defaults to 127.0.0.1 if null/empty.</param>
        /// <param name="cancellationToken">Cancellation token for connect/handshake operations.</param>
        /// <returns>Tuple (uid, publicKeyDer) on success; empty values on failure.</returns>
        public async Task<(Guid uid, byte[] publicKeyDer)> ConnectToServerAsync(
            string username,
            string ipAddressOfServer,
            CancellationToken cancellationToken = default)
        {
            try
            {
                /// <summary> Closes/disposes any previous socket to ensure a clean start </summary>
                try 
                { 
                    _tcpClient?.Close(); 
                } 
                catch { }
                
                try 
                { 
                    _tcpClient?.Dispose(); 
                } 
                catch { }

                /// <summary> Creates a fresh TCP client instance </summary>
                _tcpClient = new TcpClient();

                /// <summary> Resolves target IP; falls back to loopback if missing </summary>
                string ipToConnect = string.IsNullOrWhiteSpace(ipAddressOfServer) ? "127.0.0.1" : ipAddressOfServer;

                /// <summary> Validates non-loopback IP format to avoid runtime parse errors </summary>
                if (ipToConnect != "127.0.0.1" && !System.Net.IPAddress.TryParse(ipToConnect, out _))
                {
                    throw new ArgumentException(LocalizationManager.GetString("IPAddressInvalid"));
                }

                /// <summary> Selects port from settings or uses the default development port </summary>
                int port = Properties.Settings.Default.UseCustomPort
                    ? Properties.Settings.Default.CustomPortNumber
                    : 7123;

                /// <summary> Opens the TCP connection asynchronously </summary>
                await _tcpClient.ConnectAsync(ipToConnect, port).ConfigureAwait(false);
                ClientLogger.Log($"TCP connection established — IP: {ipToConnect}, Port: {port}", ClientLogLevel.Debug);

                /// <summary> Binds a new PacketReader to the active network stream </summary>
                _packetReader = new PacketReader(_tcpClient.GetStream());

                /// <summary> Ensures a lock to serialize critical read sections </summary>
                if (_readerLock == null)
                {
                    _readerLock = new SemaphoreSlim(1, 1);
                }

                /// <summary> Generates a per-session UID </summary>
                LocalUid = Guid.NewGuid();

                /// <summary> Initializes public key for handshake (real if encryption enabled, dummy otherwise) </summary>
                if (Properties.Settings.Default.UseEncryption && _encryptionPipeline != null)
                {
                    LocalPublicKey = _encryptionPipeline.PublicKeyDer;

                    /// <summary> Guards against missing/empty public key prior to handshake </summary>
                    if (LocalPublicKey == null || LocalPublicKey.Length == 0)
                    {
                        throw new InvalidOperationException("Public key not initialized");
                    }
                }
                else
                {
                    /// <summary> Use a dummy but valid DER key to satisfy handshake format </summary>
                    LocalPublicKey = EncryptionHelper.PublicKeyDer;
                }

                /// <summary> Creates a handshake completion TCS to coordinate readiness </summary>
                _handshakeCompletionTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

                /// <summary> Sends initial handshake and awaits server ACK </summary>
                bool handshakeConfirmed = await SendInitialConnectionPacketAsync(username, LocalUid, LocalPublicKey, cancellationToken)
                    .ConfigureAwait(false);
                if (!handshakeConfirmed)
                {
                    ClientLogger.LogLocalized(LocalizationManager.GetString("ErrorFailedToSendInitialHandshake"), ClientLogLevel.Error);

                    /// <summary> Cleans up connection state on handshake failure </summary>
                    CleanConnection();

                    /// <summary> Cancels and releases handshake TCS to avoid dangling tasks </summary>
                    _handshakeCompletionTcs?.TrySetCanceled();
                    _handshakeCompletionTcs = null;

                    /// <summary> Returns sentinel values to signal failure to caller </summary>
                    return (Guid.Empty, Array.Empty<byte>());
                }

                /// <summary> Completes handshake and delegates pipeline readiness </summary>
                MarkHandshakeComplete(LocalUid, LocalPublicKey);

                /// <summary> Notifies subscribers that the connection is established </summary>
                ConnectionEstablished?.Invoke();

                /// <summary> Starts background packet reading with a dedicated cancellation token </summary>
                _connectionCts = new CancellationTokenSource();
                _ = Task.Run(() => ReadPacketsAsync(_connectionCts.Token));

                /// <summary> Returns the established UID and public key to the caller </summary>
                return (LocalUid, LocalPublicKey);
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("ConnectToServerAsync canceled", ClientLogLevel.Debug);

                /// <summary> Cleans up connection resources after cancellation </summary>
                CleanConnection();

                /// <summary> Propagates cancellation to the handshake TCS and clears it </summary>
                _handshakeCompletionTcs?.TrySetCanceled();
                _handshakeCompletionTcs = null;

                /// <summary> Returns sentinel values to indicate cancellation to the caller </summary>
                return (Guid.Empty, Array.Empty<byte>());
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"ConnectToServerAsync failed: {ex.Message}", ClientLogLevel.Error);

                /// <summary> Ensures a clean teardown on unexpected errors </summary>
                CleanConnection();

                /// <summary> Cancels and releases handshake TCS on failure </summary>
                _handshakeCompletionTcs?.TrySetCanceled();
                _handshakeCompletionTcs = null;

                /// <summary> Returns sentinel values to indicate failure to the caller </summary>
                return (Guid.Empty, Array.Empty<byte>());
            }
        }

        /// <summary>
        /// Gracefully notifies server (if possible), cancels background readers,
        /// and tears down network resources asynchronously.
        /// This keeps network I/O off the UI thread and exposes a Task-based API.
        /// </summary>
        public async Task DisconnectFromServerAsync(CancellationToken cancellationToken = default)
        {
            // Ensures single concurrent execution
            if (Interlocked.Exchange(ref _disconnectFromServerCalled, 1) != 0)
                return;

            try
            {
                // Tries to send a disconnect notify before closing sockets
                try
                {
                    await SendDisconnectNotifyToServerAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"SendDisconnectNotifyToServerAsync failed: {ex.Message}", ClientLogLevel.Warn);
                }

                // Cancels background readers first so they stop using the stream
                try
                {
                    _connectionCts?.Cancel();
                    _connectionCts?.Dispose();
                    _connectionCts = null;
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"Connection cancellation failed: {ex.Message}", ClientLogLevel.Warn);
                }

                // Closes and disposes the network stream and client
                try
                {
                    _packetReader = null!;
                    _tcpClient?.GetStream()?.Close();
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"NetworkStream close failed: {ex.Message}", ClientLogLevel.Warn);
                }

                try
                {
                    _tcpClient?.Close();
                    _tcpClient?.Dispose();
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"TcpClient cleanup failed: {ex.Message}", ClientLogLevel.Warn);
                }

                // Resets counters and notify listeners
                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);
                ConnectionTerminated?.Invoke();
            }
            finally
            {
                // Allows future disconnect calls and reset init flag
                Volatile.Write(ref _disconnectFromServerCalled, 0);
                Volatile.Write(ref _encryptionInitOnce, 0);
            }
        }

        /// <summary> 
        /// Returns all known public RSA keys for connected users. 
        /// Filters out users with empty UID or missing public key bytes 
        /// and returns a Dictionary keyed by Guid with DER byte[] values. 
        /// A Dictionary is a collection of key/value pairs that allows 
        /// fast lookup of a value by its unique key; 
        /// here the key is the user’s Guid and the value is the user’s 
        /// public key in DER format.
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
        /// Marks the client-side handshake as complete, completes the TCS,
        /// and initializes the encryption pipeline only if encryption is enabled.
        /// </summary>
        public void MarkHandshakeComplete(Guid uid, byte[] publicKeyDer)
        {
            // Completes the handshake TCS
            var tcs = _handshakeCompletionTcs;
            if (tcs == null)
            {
                _handshakeCompletionTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                _handshakeCompletionTcs.TrySetResult(true);
            }
            else
            {
                tcs.TrySetResult(true);
            }

            // Initialize pipeline only if encryption is enabled
            if (Settings.Default.UseEncryption && _encryptionPipeline != null)
            {
                _encryptionPipeline.MarkReadyForSession(uid, publicKeyDer);
                ClientLogger.Log(
                    $"MarkHandshakeComplete — UID={uid}, PublicKeyLen={publicKeyDer?.Length}",
                    ClientLogLevel.Debug
                );
            }
            else
            {
                ClientLogger.Log("MarkHandshakeComplete — encryption disabled, pipeline not initialized.", ClientLogLevel.Info);
            }
        }

        /// <summary>
        /// Background task that continuously reads framed packets until the connection closes.
        /// • Reads length‑prefixed payloads with PacketReader.
        /// • Dispatches roster and message updates to the UI thread.
        /// • Completes handshake when HandshakeAck is received.
        /// • Stops gracefully on cancellation, stream close, or protocol error.
        /// 
        /// Notes:
        /// - Single reader invariant: all frame reads go through _packetReader.
        /// - Each frame is parsed in-memory to keep the network stream position aligned.
        /// </summary>
        private async Task ReadPacketsAsync(CancellationToken cancellationToken)
        {
            // Captures ViewModel reference on the UI thread
            MainViewModel viewModel = null!;

            // Captures ViewModel without blocking the network read thread
            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mw)
                    viewModel = mw.ViewModel;
            }).Task.ConfigureAwait(false);

            if (viewModel == null)
            {
                return;
            }

            // Ensures we don't start reading from the shared PacketReader until any handshake reader
            // that holds _readerLock has finished consuming its frame.
            await _readerLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            
            try
            {
                // Continuous read loop. This method must be the only continuous reader of frames.
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (_tcpClient == null || !_tcpClient.Connected)
                    {
                        ClientLogger.Log("ReadPackets: socket not connected, exiting.", ClientLogLevel.Info);
                        break;
                    }

                    byte[] framedBody;
                    
                    try
                    {
                        // Reads the next framed body via the shared PacketReader (single-reader invariant).
                        framedBody = await _packetReader!.ReadFramedBodyAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        // Cancellation requested — exits gracefully.
                        break;
                    }

                    if (framedBody == null || framedBody.Length == 0)
                    {
                        ClientLogger.Log("ReadPackets: remote closed stream or empty frame", ClientLogLevel.Info);
                        break;
                    }

                    try
                    {
                        // Parses the frame in-memory to avoid touching the underlying NetworkStream.
                        using var ms = new MemoryStream(framedBody, writable: false);
                        var reader = new PacketReader(ms);

                        // Opcode is first byte of the framed payload.
                        byte opcodeByte = await reader.ReadByteAsync(cancellationToken).ConfigureAwait(false);
                        var opcode = (ClientPacketOpCode)opcodeByte;
                        ClientLogger.Log($"RECEIVED_PACKET_OPCODE={(byte)opcode}", ClientLogLevel.Debug);

                        switch (opcode)
                        {
                            case ClientPacketOpCode.RosterBroadcast:
                                // Resets unexpected-opcode counter when a valid packet is processed.
                                if (_consecutiveUnexpectedOpcodes != 0)
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                // Reads roster count (network-order int) and then entries.
                                int totalUsers = await reader.ReadInt32NetworkOrderAsync(cancellationToken).ConfigureAwait(false);

                                var rosterEntries = new List<(Guid UserId, string Username, byte[] PublicKeyDer)>(totalUsers);
                                for (int i = 0; i < totalUsers; i++)
                                {
                                    Guid userId = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    string username = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);
                                    byte[] publicKeyDer = await reader.ReadBytesWithLengthAsync(maxAllowed: 64 * 1024, cancellationToken).ConfigureAwait(false);
                                    rosterEntries.Add((userId, username, publicKeyDer));
                                }

                                // Posts UI update without blocking the background read loop
                                _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                                {
                                    viewModel.DisplayRosterSnapshot(rosterEntries);
                                }));
                                break;

                            case ClientPacketOpCode.HandshakeAck:
                                {
                                    // Signals handshake completion
                                    _handshakeCompletionTcs?.TrySetResult(true);
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    // Sends public key only once if encryption is active
                                    if (EncryptionHelper.IsEncryptionActive && !_hasSentPublicKey)
                                    {
                                        await SendPublicKeyToServerAsync(LocalUid, EncryptionHelper.PublicKeyDer, cancellationToken).ConfigureAwait(false);

                                        _hasSentPublicKey = true; // local flag to prevent multiple sends
                                        ClientLogger.Log("Public key sent once after ACK.", ClientLogLevel.Debug);
                                    }

                                    break;
                                }

                            case ClientPacketOpCode.PlainMessage:
                                
                                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                // Payload: [16-byte sender UID][16-byte recipient UID placeholder][length-prefixed UTF-8 text]
                                Guid senderUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false); // discard recipient placeholder
                                string message = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                string senderName = viewModel.Users.FirstOrDefault(u => u.UID == senderUid)?.Username ?? senderUid.ToString();

                                // Posts UI update without blocking network read loop
                                _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                                {
                                    viewModel.OnPlainMessageReceived(senderName, message);
                                }));

                                break;

                            case ClientPacketOpCode.EncryptedMessage:
                                {
                                    // Resets unexpected opcode counter.
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    // Reads sender UID and discards recipient UID (not needed on client side).
                                    Guid encryptedSenderUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    // Reads ciphertext payload.
                                    byte[] cipherBytes = await reader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);

                                    // Resolves sender name for display.
                                    string encryptedSenderName = viewModel.Users.FirstOrDefault(u => u.UID == encryptedSenderUid)?.Username
                                                                 ?? encryptedSenderUid.ToString();

                                    // Validates payload presence.
                                    if (cipherBytes == null || cipherBytes.Length == 0)
                                    {
                                        ClientLogger.Log("Encrypted payload empty; dropping.", ClientLogLevel.Warn);
                                        break;
                                    }

                                    string plainText;

                                    // Decrypts only when encryption is active.
                                    if (EncryptionHelper.IsEncryptionActive)
                                    {
                                        try
                                        {
                                            // Performs synchronous RSA-OAEP-SHA256 decryption.
                                            plainText = EncryptionHelper.DecryptMessageFromBytes(cipherBytes);
                                        }
                                        catch (Exception ex)
                                        {
                                            ClientLogger.Log($"Decrypt failed: {ex.Message}", ClientLogLevel.Error);
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        // Falls back to raw display when encryption is inactive.
                                        plainText = Encoding.UTF8.GetString(cipherBytes);
                                        ClientLogger.Log("EncryptedMessage received while encryption inactive; showing raw text.", ClientLogLevel.Warn);
                                    }

                                    // Dispatches plaintext to UI thread for rendering.
                                    _ = Application.Current.Dispatcher.BeginInvoke(() =>
                                    {
                                        viewModel.OnPlainMessageReceived(encryptedSenderName, plainText);
                                    });

                                    break;
                                }

                            case ClientPacketOpCode.PublicKeyResponse:
                                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                Guid originUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                byte[] keyDer = await reader.ReadBytesWithLengthAsync(maxAllowed: null, cancellationToken).ConfigureAwait(false);
                                _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false); // discards requester UID

                                _ = Application.Current.Dispatcher.BeginInvoke(() =>
                                {
                                    viewModel.OnPublicKeyReceived(originUid, keyDer);
                                });
                                break;

                            case ClientPacketOpCode.DisconnectNotify:
                                
                                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                Guid discUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                string discName = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);
                                
                                _ = Application.Current.Dispatcher.BeginInvoke(() => viewModel.OnUserDisconnected(discUid, discName));
                                break;

                            case ClientPacketOpCode.ForceDisconnectClient:
                                
                                // Server demanded immediate disconnect; informs UI and exits.
                                _ = Application.Current.Dispatcher.BeginInvoke(() => viewModel.OnDisconnectedByServer());
                                return;

                            default:
                                
                                // Unexpected opcode: increments counter and optionally disconnects if threshold reached.
                                ClientLogger.Log($"Unexpected opcode 0x{opcodeByte:X2} in framed packet", ClientLogLevel.Warn);

                                if (Interlocked.Increment(ref _consecutiveUnexpectedOpcodes) >= 3)
                                {
                                    ClientLogger.Log("Too many consecutive unexpected opcodes, initiating graceful disconnect.", ClientLogLevel.Warn);
                                    _ = Application.Current.Dispatcher.BeginInvoke(() => viewModel.OnDisconnectedByServer());
                                    return;
                                }
                                break;
                        }
                    }
                    catch (InvalidDataException ide)
                    {
                        // Protocol-level error detected while parsing a frame; aborts read loop to force reconnect/cleanup.
                        ClientLogger.Log($"ReadPackets protocol error: {ide.Message}", ClientLogLevel.Warn);
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        // Cancellation observed while parsing — exits gracefully.
                        break;
                    }
                    catch (Exception ex)
                    {
                        // Non-fatal processing error; logs and continue reading next frames.
                        ClientLogger.Log($"ReadPackets processing error: {ex.Message}", ClientLogLevel.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                // Fatal error in the reader loop — logs for diagnostics.
                ClientLogger.Log($"ReadPackets fatal error: {ex.Message}", ClientLogLevel.Error);
            }
            finally
            {
                // Always release the reader lock to avoid blocking other consumers on errors
                try
                {
                    _readerLock.Release();
                }
                catch { }

                // Notifies UI asynchronously to avoid blocking the network read loop
                try
                {
                    _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                    {
                        viewModel.OnDisconnectedByServer();
                    }));
                }
                catch { }

                // Performs centralized cleanup to reset connection state
                try
                {
                    CleanConnection();
                }
                catch { }

                // Resets opcode counter on disconnect/cleanup
                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);
            }
        }

        /// <summary>
        /// Sends a PublicKeyRequest packet to the server asynchronously to retrieve known public keys.
        /// Gets this client's UID, ensures the packet is framed and sent atomically,
        /// allows cancellation and logs activity.
        /// </summary>
        public async Task SendRequestAllPublicKeysFromServerAsync(CancellationToken cancellationToken)
        {
            try
            {
                var packetBuilder = new PacketBuilder();
                packetBuilder.WriteOpCode((byte)ClientPacketOpCode.PublicKeyRequest);
                packetBuilder.WriteUid(LocalUid);

                byte[] payload = packetBuilder.GetPacketBytes();

                // Use unified writer instead of direct stream writes
                await SendFramedAsync(payload, cancellationToken).ConfigureAwait(false);

                ClientLogger.Log($"Public key sync request sent — UID: {LocalUid}", ClientLogLevel.Debug);
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("SendRequestAllPublicKeysFromServer cancelled.", ClientLogLevel.Debug);
                throw;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Public key request failed: {ex.Message}", ClientLogLevel.Error);
            }
        }

        /// <summary>
        /// Sends a framed DisconnectNotify packet to the server asynchronously.
        /// Gets the disconnect UID, ensures the packet is framed and sent atomically,
        /// allows cancellation via the provided token.
        /// </summary>
        public async Task SendDisconnectNotifyToServerAsync(CancellationToken cancellationToken)
        {
            try
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ClientPacketOpCode.DisconnectNotify);
                builder.WriteUid(LocalUid);

                byte[] payload = builder.GetPacketBytes();

                // Use the connection-level sender that frames + serializes writes
                await SendFramedAsync(payload, cancellationToken).ConfigureAwait(false);

                ClientLogger.Log($"Sent DisconnectNotify for {LocalUid}", ClientLogLevel.Debug);
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("SendDisconnectNotifyToServer cancelled.", ClientLogLevel.Debug);
                throw;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"DisconnectNotify failed: {ex.Message}", ClientLogLevel.Warn);
            }
        }

        /// <summary>
        /// • Frames (wraps) the raw payload with a length header so the receiver knows how many bytes to read.
        /// • Serializes all writes with a shared lock to prevent interleaving data when multiple tasks send at once.
        /// • Captures the NetworkStream and checks it is writable before sending.
        /// • Writes the framed bytes asynchronously and awaits completion for proper back-pressure.
        /// • Handles cancellation and common I/O/disposal errors cleanly, then releases the lock.
        /// </summary>
        private async Task SendFramedAsync(byte[] payload, CancellationToken cancellationToken)
        {
            // If payload is null, uses an empty array to avoid null-reference issues.
            if (payload == null)
            {
                payload = Array.Empty<byte>();
            }

            /// <summary>
            /// Framing.Frame adds a fixed-size length prefix (4 bytes) before the payload, so the receiver
            /// can read "length" first, then exactly "length" bytes of the payload — preventing misaligned reads.
            ///</summary >
            var framed = Framing.Frame(payload);

            /// <summary>
            /// _writeLock ensures that only one sender writes to the NetworkStream at a time.
            /// Without this, concurrent writes can interleave bytes and corrupt the framing protocol.
            /// </summary>
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                /// <summary>
                /// Gets the stream once to avoid races if _tcpClient changes or is disposed by another thread.
                /// </summary >
                var stream = _tcpClient.GetStream();

                // If the stream cannot write, fails fast with a clear message.
                if (stream is null || !stream.CanWrite)
                {
                    throw new InvalidOperationException("NetworkStream is not writable.");
                }

                // WriteAsync sends the framed bytes to the network without blocking the calling thread.
                // We await it to apply back-pressure: if the OS buffer is full, we pause until it can accept more data.
                await stream.WriteAsync(framed, 0, framed.Length, cancellationToken).ConfigureAwait(false);

                // Note: FlushAsync on NetworkStream is useless in this context (no-op) for TCP; writes are pushed as they happen.
            }
            catch (OperationCanceledException)
            {
                // If the cancellationToken was triggered, propagate the cancellation to the caller.
                throw;
            }
            catch (ObjectDisposedException ex)
            {
                // The stream (or client) was disposed during write: surface a clear, high-level error.
                throw new InvalidOperationException("Connection stream disposed during write.", ex);
            }
            catch (IOException ex)
            {
                // I/O failure (e.g., remote closed connection): wrap with a descriptive message.
                throw new InvalidOperationException("Connection write failed.", ex);
            }
            finally
            {
                // Always release the write lock so other sends can proceed, even if an error occurred.
                _writeLock.Release();
            }
        }

        /// <summary>
        /// Build and send the framed handshake packet, then consume 
        /// exactly one framed response (HandshakeAck) using the shared
        /// PacketReader protected by _readerLock.
        /// Packet on wire: 
        /// [4-byte big-endian length][1-byte opcode][username (length-prefixed UTF-8)] 
        /// [16-byte UID][4-byte publicKeyDer length][publicKeyDer bytes] 
        /// </summary>
        /// <return>
        /// True only if the ack opcode matches ClientPacketOpCode.HandshakeAck.
        /// </return>
        public async Task<bool> SendInitialConnectionPacketAsync(string username, Guid uid,
            byte[] publicKeyDer, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                _handshakeCompletionTcs?.TrySetCanceled(); // cancel on invalid input
                return false;
            }

            if (_tcpClient == null || !_tcpClient.Connected)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync failed: socket not connected.", ClientLogLevel.Error);
                _handshakeCompletionTcs?.TrySetCanceled(); // cancel on no socket
                return false;
            }

            if (uid == Guid.Empty)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync failed: UID is empty.", ClientLogLevel.Error);
                _handshakeCompletionTcs?.TrySetCanceled(); // cancel on invalid uid
                return false;
            }

            if (publicKeyDer == null)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync failed: publicKeyDer is null.", ClientLogLevel.Error);
                _handshakeCompletionTcs?.TrySetCanceled(); // cancel on invalid public key
                return false;
            }

            try
            {
                // Builds the payload: opcode + username + uid + length-prefixed public key.
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ClientPacketOpCode.Handshake);
                builder.WriteString(username);
                builder.WriteUid(uid);
                builder.WriteBytesWithLength(publicKeyDer);
                byte[] payload = builder.GetPacketBytes();
                
                // Frames header: 4-byte big-endian length
                int len = payload.Length;
                byte[] header = new byte[4];
                header[0] = (byte)(len >> 24);
                header[1] = (byte)(len >> 16);
                header[2] = (byte)(len >> 8);
                header[3] = (byte)len;

                NetworkStream stream = _tcpClient.GetStream();

                // Diagnostic logs for handshake bytes.
                ClientLogger.Log($"SENDING_HANDSHAKE_HEADER={BitConverter.ToString(header)} LEN={payload.Length}", ClientLogLevel.Debug);
                ClientLogger.Log($"SENDING_HANDSHAKE_PAYLOAD_PREFIX={BitConverter.ToString(payload, 0, Math.Min(16, payload.Length))}", ClientLogLevel.Debug);

                // Writes header + payload atomically and flush.
                await stream.WriteAsync(header, 0, header.Length, cancellationToken).ConfigureAwait(false);
                if (payload.Length > 0)
                    await stream.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

                // Asynchronously waits to enter the reader lock (a SemaphoreSlim)
                // and ensures the current async method gains exclusive,
                // cancellable access to the shared PacketReader,
                // before attempting to read a single framed response from the network.
                await _readerLock.WaitAsync(cancellationToken).ConfigureAwait(false);

                try
                {
                    // Reads a single framed body (4-byte length prefix + payload) via shared PacketReader.
                    byte[] frame = await _packetReader!.ReadFramedBodyAsync(cancellationToken).ConfigureAwait(false);
                    if (frame == null || frame.Length == 0)
                    {
                        ClientLogger.Log("Handshake failed: empty ack frame", ClientLogLevel.Error);
                        _handshakeCompletionTcs?.TrySetCanceled(); // cancel on empty frame
                        return false;
                    }

                    // First byte of frame payload is the opcode.
                    byte receivedOpcode = frame[0];
                    ClientLogger.Log($"RECEIVED_PACKET_OPCODE={receivedOpcode}", ClientLogLevel.Debug);

                    if (receivedOpcode != (byte)ClientPacketOpCode.HandshakeAck)
                    {
                        ClientLogger.Log($"Unexpected packet opcode while waiting for HandshakeAck: {receivedOpcode}", ClientLogLevel.Error);
                        _handshakeCompletionTcs?.TrySetCanceled(); // cancel on unexpected opcode
                        return false;
                    }

                    // Ack validated successfully.
                    return true;
                }
                finally
                {
                    _readerLock.Release();
                }
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync cancelled by token.", ClientLogLevel.Debug);
                _handshakeCompletionTcs?.TrySetCanceled(); // cancel on cancellation
                return false;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"SendInitialConnectionPacketAsync exception: {ex.Message}", ClientLogLevel.Error);
                _handshakeCompletionTcs?.TrySetCanceled(); // cancel on unexpected exception
                return false;
            }
        }

        /// <summary>
        /// Sends a chat message to the server.
        /// Chooses plain or encrypted mode depending on user settings and runtime readiness.
        /// Validates session, recipients, and public key availability before attempting encryption.
        /// Returns true if the message was successfully sent.
        /// </summary>
        public async Task<bool> SendMessageAsync(string plainText, CancellationToken cancellationToken)
        {
            // Avoids sending empty messages
            if (string.IsNullOrWhiteSpace(plainText))
                return false;

            // Ensures main window, view model, and local user are available
            if (Application.Current.MainWindow is not MainWindow mainWindow ||
                mainWindow.ViewModel is not MainViewModel viewModel ||
                viewModel.LocalUser == null)
                return false;

            Guid senderUid = viewModel.LocalUser.UID;

            // Builds recipient list (normal path if peers exist)
            var recipients = viewModel.Users.Where(u => u.UID != senderUid).ToList();
            bool messageSent = false;

            /// <summary>
            /// --- Normal path: send to each peer ---
            /// </ summary >
            if (recipients.Count >= 1)
            {
                foreach (var recipient in recipients)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Guid recipientUid = recipient.UID;

                    var packet = new PacketBuilder();

                    /// <summary >
                    /// Decides encryption mode:
                    /// toggle ON + runtime ready → encrypted,
                    /// else plain
                    /// </ summary >
                    bool useEncryptionNow = Properties.Settings.Default.UseEncryption && viewModel.IsEncryptionReady;

                    // Logs decision path for message encryption
                    ClientLogger.Log($"SendMessageAsync: recipient={recipientUid}, useEncryptionNow={useEncryptionNow}", ClientLogLevel.Debug);

                    /// <summary>
                    /// --- Send Plain message ---
                    /// </ summary >
                    if (!useEncryptionNow)
                    {
                        // [opcode][senderUid][string]
                        packet.WriteOpCode((byte)ClientPacketOpCode.PlainMessage);
                        packet.WriteUid(senderUid);
                        packet.WriteString(plainText);
                    }
                    /// <summary>
                    /// --- Send encrypted message ---
                    /// </ summary >
                    else
                    {
                        // Lookup recipient public key
                        byte[] publicKeyDer;
                        lock (viewModel.KnownPublicKeys)
                        {
                            /// <summary>
                            /// Attempts to retrieve the recipient's RSA public key (DER format) from the dictionary.
                            /// If found, it is returned in 'keyFound'; if not, 'keyFound' remains null and encryption cannot proceed.
                            /// </ summary >
                            viewModel.KnownPublicKeys.TryGetValue(recipientUid, out byte[]? keyFound);

                            publicKeyDer = keyFound ?? Array.Empty<byte>();
                        }

                        if (publicKeyDer.Length == 0)
                        {
                            ClientLogger.Log($"Missing public key for recipient {recipientUid}.", ClientLogLevel.Warn);
                            continue;
                        }

                        /// <summary>
                        /// Encrypt plaintext with recipient's RSA public key (DER format)
                        /// </summary>
                        byte[] cipherArray = EncryptionHelper.EncryptMessageToBytes(plainText, publicKeyDer);
                        if (cipherArray == null || cipherArray.Length == 0)
                        {
                            ClientLogger.Log($"Encryption failed for recipient {recipientUid}.", ClientLogLevel.Error);
                            continue;
                        }

                        // [opcode][senderUid][recipientUid][bytes-with-length]
                        packet.WriteOpCode((byte)ClientPacketOpCode.EncryptedMessage);
                        packet.WriteUid(senderUid);
                        packet.WriteUid(recipientUid);
                        packet.WriteBytesWithLength(cipherArray);
                    }

                    try
                    {
                        await SendFramedAsync(packet.GetPacketBytes(), cancellationToken).ConfigureAwait(false);
                        messageSent = true;

                        // Logs successful send
                        ClientLogger.Log($"Message successfully sent to {recipientUid}. Encrypted={useEncryptionNow}", ClientLogLevel.Info);
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"Failed to send message to {recipientUid}: {ex.Message}", ClientLogLevel.Error);
                    }
                }
            }

            /// <summary>
            /// --- Solo mode: recipient is the sender ---
            /// </summary>
            else
            {
                cancellationToken.ThrowIfCancellationRequested();
                Guid recipientUid = senderUid;

                var packet = new PacketBuilder();
                bool useEncryptionNow = Properties.Settings.Default.UseEncryption && viewModel.IsEncryptionReady;

                // Logs decision path for self-message
                ClientLogger.Log($"SendMessageAsync (solo): useEncryptionNow={useEncryptionNow}", ClientLogLevel.Debug);

                /// <summary<>
                /// --- Send Plain self-message ---
                /// </summary>
                if (!useEncryptionNow)
                {
                    // [opcode][senderUid][string]
                    packet.WriteOpCode((byte)ClientPacketOpCode.PlainMessage);
                    packet.WriteUid(senderUid);
                    packet.WriteString(plainText);
                }

                /// <summary>
                /// --- Encrypted self-message ---
                /// </ summary >
                else
                {
                    // Looks-up local public key
                    byte[] publicKeyDer;
                    lock (viewModel.KnownPublicKeys)
                    {
                        viewModel.KnownPublicKeys.TryGetValue(senderUid, out byte[]? keyFound);
                        publicKeyDer = keyFound ?? Array.Empty<byte>();
                    }

                    if (publicKeyDer.Length == 0)
                    {
                        ClientLogger.Log($"Missing local public key for self-message.", ClientLogLevel.Warn);
                        return false;
                    }

                    // Encrypts plaintext with local RSA public key (DER format)
                    byte[] cipherArray = EncryptionHelper.EncryptMessageToBytes(plainText, publicKeyDer);
                    if (cipherArray == null || cipherArray.Length == 0)
                    {
                        ClientLogger.Log("Encryption failed for self-message.", ClientLogLevel.Error);
                        return false;
                    }

                    // [opcode][senderUid][recipientUid][bytes-with-length]
                    packet.WriteOpCode((byte)ClientPacketOpCode.EncryptedMessage);
                    packet.WriteUid(senderUid);
                    packet.WriteUid(recipientUid);
                    packet.WriteBytesWithLength(cipherArray);
                }

                try
                {
                    await SendFramedAsync(packet.GetPacketBytes(), cancellationToken).ConfigureAwait(false);
                    messageSent = true;

                    // Logs successful self-message send
                    ClientLogger.Log($"Self-message successfully sent. Encrypted={useEncryptionNow}", ClientLogLevel.Info);
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"Failed to send self-message: {ex.Message}", ClientLogLevel.Error);
                }
            }

            return messageSent;
        }

        /// <summary>
        /// Sends the client's public RSA key to the server asynchronously.
        /// Gets the target UID and DER bytes, ensures packet is framed and sent atomically,
        /// allows cancellation and returns true on success.
        /// </summary>
        public async Task<bool> SendPublicKeyToServerAsync(Guid targetUid, byte[] publicKeyDer, CancellationToken cancellationToken)
        {
            // Validates connection early
            if (_tcpClient?.Client == null || !_tcpClient.Connected)
            {
                ClientLogger.Log("Cannot send public key — client is not connected.", ClientLogLevel.Error);
                return false;
            }

            try
            {
                // Builds the packet with required fields
                var publicKeyPacket = new PacketBuilder();
                publicKeyPacket.WriteOpCode((byte)ClientPacketOpCode.PublicKeyResponse);
                publicKeyPacket.WriteUid(targetUid);
                publicKeyPacket.WriteBytesWithLength(publicKeyDer);

                ClientLogger.Log($"Sending public key — UID: {targetUid}, Key length: {publicKeyDer.Length}", ClientLogLevel.Debug);

                // Sends the raw payload via unified sender
                await SendFramedAsync(publicKeyPacket.GetPacketBytes(), cancellationToken).ConfigureAwait(false);

                ClientLogger.Log("Public key packet sent successfully.", ClientLogLevel.Debug);
                return true;
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("SendPublicKeyToServer cancelled.", ClientLogLevel.Debug);
                throw;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Public key send failed: {ex.Message}", ClientLogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// Builds and sends a PublicKeyRequest packet to the server asynchronously.
        /// Gets the target UID, ensures the packet is framed and sent atomically,
        /// allows cancellation and logs the result.
        /// </summary>
        public async Task SendRequestToPeerForPublicKeyAsync(Guid targetUid, CancellationToken cancellationToken)
        {
            try
            {
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)ClientPacketOpCode.PublicKeyRequest);
                builder.WriteUid(LocalUid);
                builder.WriteUid(targetUid);

                byte[] payload = builder.GetPacketBytes();

                // Sends via unified send helper
                await SendFramedAsync(payload, cancellationToken).ConfigureAwait(false);

                ClientLogger.Log($"Requested public key for {targetUid}.", ClientLogLevel.Debug);
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log($"Key request for {targetUid} cancelled.", ClientLogLevel.Debug);
                throw;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Key request for {targetUid} failed: {ex.Message}", ClientLogLevel.Error);
            }
        }
    }
}
