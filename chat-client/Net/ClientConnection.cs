/// <file>ClientConnection.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 28th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.MVVM.View;
using chat_protocol.Net.IO;
using chat_protocol.Net;
using chat_client.Properties;
using System.IO;
using System.Net.Sockets;
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

        // Reader lock to serialize critical reads and avoid concurrent consumption of the NetworkStream.
        // This field may be reset by CleanConnection to guarantee a fresh, uncontended semaphore.
        private SemaphoreSlim _readerLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Maintains the active TCP client connection to the server.
        /// Used for sending and receiving framed packets over the network.
        /// </summary>
        private TcpClient _tcpClient;

        /// <summary>
        /// Reference to the main ViewModel (set at connection init)
        /// </summary>
        private readonly MainViewModel _viewModel;

        /// <summary>
        /// Callback used to run actions on the UI thread, ensuring safe property updates.
        /// </summary>
        private readonly Action<Action> _uiDispatcherInvoke;

        // Single-writer guard for this connection instance; kept readonly for the connection lifetime.
        private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);

        // Dictionary of known public keys for peers (UID → DER key)
        private readonly Dictionary<Guid, byte[]> KnownPublicKeys = new Dictionary<Guid, byte[]>();

        // PUBLIC PROPERTIES

        /// <summary>
        /// Reference to the encryption pipeline, may be null when encryption is disabled.
        /// </summary>
        public EncryptionPipeline? EncryptionPipeline { get; set; }

        /// <summary>Indicates whether the client is currently connected to the server.</summary>
        public bool IsConnected => _tcpClient?.Connected ?? false;

        /// <summary>Indicates whether the TCP socket is connected and the handshake(HandshakeAck) 
        /// has been successfully confirmed</summary>
        public bool IsEstablished => IsConnected && _handshakeCompletionTcs != null 
            && _handshakeCompletionTcs.Task.IsCompletedSuccessfully && _handshakeCompletionTcs.Task.Result == true;

        /// <summary>
        /// Tracks whether key synchronization is ongoing
        /// </summary>
        public bool IsSyncingKeys { get; private set; }

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
        /// prepares key storage, and stores the UI dispatcher dependency provided by MainViewModel.
        /// </summary>
        /// <param name="uiDispatcherInvoke">UI dispatcher callback provided by MainViewModel.</param>
        public ClientConnection(Action<Action> uiDispatcherInvoke, MainViewModel viewModel)
        {
            /// <summary> Creates the underlying TCP client used for communication </summary>
            _tcpClient = new TcpClient();

            /// <summary> Resets local identifiers for a fresh session </summary>
            LocalUid = Guid.Empty;

            /// <summary> Initializes local public key storage as empty </summary>
            LocalPublicKey = Array.Empty<byte>();

            /// <summary> Initializes dictionary of known public keys for peers </summary>
            KnownPublicKeys = new Dictionary<Guid, byte[]>();

            /// <summary> Stores the UI dispatcher callback passed from MainViewModel </summary>
            _uiDispatcherInvoke = uiDispatcherInvoke ?? throw new ArgumentNullException(nameof(uiDispatcherInvoke));

            /// <summary> Captures reference to the main ViewModel for later use </summary>
            _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));

            /// <summary> Initializes encryption state flags </summary>
            _viewModel.ResetEncryptionPipelineAndUI();
            IsSyncingKeys = false;
        }

        /// <summary>
        /// Cleanly resets the client connection state:
        /// • Cancels and disposes any pending handshake TaskCompletionSource to wake awaiters
        /// • Cancels and disposes the connection CancellationTokenSource to stop the background reader
        /// • Disposes the TcpClient (which also closes the NetworkStream) and reinitializes a fresh instance
        /// • Clears the PacketReader backing field (not IDisposable)
        /// • Disposes and recreates the reader lock to ensure a fresh semaphore
        /// • Resets handshake/encryption flags and user disconnect flag to ensure fresh state
        /// • UI update is delegated to the caller
        /// </summary>
        private void CleanConnection()
        {
            /// <summary> Resets handshake and encryption flags for a fresh state </summary>
            _hasSentPublicKey = false;
            _viewModel.ResetEncryptionPipelineAndUI();
            Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

            /// <summary> Cancels handshake TCS to wake any awaiters </summary>
            _handshakeCompletionTcs?.TrySetCanceled();
            _handshakeCompletionTcs = null;

            /// <summary> Cancels and disposes connection CTS to stop read loop </summary>
            _connectionCts?.Cancel();
            _connectionCts?.Dispose();
            _connectionCts = null;

            /// <summary> Disposes TcpClient safely </summary>
            try
            {
                _tcpClient?.Close();
                _tcpClient?.Dispose();
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"CleanConnection: TcpClient dispose error — {ex.Message}", ClientLogLevel.Warn);
            }
            finally
            {
                /// <summary> Reinitializes a fresh socket </summary>
                _tcpClient = new TcpClient();
            }

            /// <summary> Clears PacketReader reference (not IDisposable) </summary>
            _packetReader = null!;

            /// <summary> Disposes and recreates the reader lock semaphore </summary>
            try
            {
                _readerLock?.Dispose();
            }
            catch
            {
                // Swallows disposal exceptions to keep shutdown resilient
            }
            _readerLock = new SemaphoreSlim(1, 1);

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

                /// <summary> Selects port from settings </summary>
                int port = Settings.Default.PortNumber;

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

                /// <summary> Generates a per-session UID that becomes the canonical ID on the server. </summary>
                LocalUid = Guid.NewGuid();

                /// <summary> Initializes public key for handshake (real if encryption enabled, dummy otherwise) </summary>
                if (Properties.Settings.Default.UseEncryption && EncryptionPipeline != null)
                {
                    LocalPublicKey = EncryptionPipeline.PublicKeyDer;

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
                    _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None);
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
                _ = Task.Run(() => ReadPacketsAsync(_connectionCts.Token), _connectionCts.Token);

                /// <summary> Returns the established UID and public key to the caller </summary>
                return (LocalUid, LocalPublicKey);
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("Connection to server canceled", ClientLogLevel.Debug);

                /// <summary> Cleans up connection resources after cancellation </summary>
                CleanConnection();

                /// <summary> Propagates cancellation to the handshake TCS and clears it </summary>
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None);
                _handshakeCompletionTcs = null;

                /// <summary> Returns sentinel values to indicate cancellation to the caller </summary>
                return (Guid.Empty, Array.Empty<byte>());
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Connection to server failed: {ex.Message}", ClientLogLevel.Error);

                /// <summary> Ensures a clean teardown on unexpected errors </summary>
                CleanConnection();

                /// <summary> Cancels and releases handshake TCS on failure </summary>
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None);
                _handshakeCompletionTcs = null;

                /// <summary> Returns sentinel values to indicate failure to the caller </summary>
                return (Guid.Empty, Array.Empty<byte>());
            }
        }

        /// <summary>
        /// Gracefully disconnects from the server.
        /// • Cancels background readers and disposes their cancellation token.  
        /// • Closes and disposes the TcpClient and its NetworkStream (only if still connected).  
        /// • Clears the PacketReader reference.  
        /// • Resets counters and notifies listeners of termination.  
        /// </summary>
        public Task DisconnectFromServerAsync(CancellationToken cancellationToken = default)
        {
            /// <summary>
            /// Ensures single concurrent execution by using Interlocked.Exchange
            /// to set the sentinel _disconnectFromServerCalled to 1.
            /// If the previous value was non-zero, another disconnect is already in progress,
            /// so the method returns immediately with a completed Task.
            /// </summary>
            if (Interlocked.Exchange(ref _disconnectFromServerCalled, 1) != 0)
                return Task.CompletedTask;

            try
            {
                /// <summary>
                /// Cancels background readers so they stop consuming the stream.
                /// Disposes the CancellationTokenSource to release unmanaged resources.
                /// </summary>
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

                /// <summary>
                /// Clears the PacketReader reference and closes the network stream
                /// only if the TcpClient is still connected.
                /// This avoids redundant close attempts on already-disconnected sockets.
                /// </summary>
                try
                {
                    _packetReader = null!;
                    if (_tcpClient?.Connected == true)
                    {
                        _tcpClient.GetStream().Close();
                    }
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"NetworkStream close failed: {ex.Message}", ClientLogLevel.Warn);
                }

                /// <summary>
                /// Closes and disposes the TcpClient safely,
                /// but only if it was instantiated.
                /// </summary>
                try
                {
                    if (_tcpClient != null)
                    {
                        if (_tcpClient.Connected)
                        {
                            _tcpClient.Close();
                        }
                        _tcpClient.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"TcpClient cleanup failed: {ex.Message}", ClientLogLevel.Warn);
                }

                /// <summary>
                /// Resets the unexpected-opcode counter and notifies listeners
                /// that the connection has been terminated.
                /// </summary>
                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);
                ConnectionTerminated?.Invoke();
            }
            finally
            {
                /// <summary>
                /// Allows future disconnect calls by resetting the sentinel,
                /// and resets the encryption init flag for clean future sessions.
                /// </summary>
                Volatile.Write(ref _disconnectFromServerCalled, 0);
                Volatile.Write(ref _encryptionInitOnce, 0);
            }

            /// <summary>
            /// Returns a completed Task to satisfy the Task-based API contract.
            /// </summary>
            return Task.CompletedTask;
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
        /// Marks the client-side handshake as complete.
        /// Completes the handshake TaskCompletionSource,
        /// assigns local identifiers and key material,
        /// and initializes the encryption pipeline only if encryption is enabled.
        /// </summary>
        /// <param name="uid">Unique identifier assigned to the local user.</param>
        /// <param name="publicKeyDer">Public key in DER format for the local user.</param>
        public void MarkHandshakeComplete(Guid uid, byte[] publicKeyDer)
        {
            /// <summary> Completes the handshake TaskCompletionSource safely </summary>
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

            /// <summary> Stores local UID and public key material </summary>
            LocalUid = uid;
            LocalPublicKey = publicKeyDer;

            /// <summary> Initializes pipeline only if encryption is enabled before handshake </summary>
            if (Settings.Default.UseEncryption && EncryptionPipeline != null)
            {
                EncryptionPipeline.MarkReadyForSession(uid, publicKeyDer);
                ClientLogger.Log($"MarkHandshakeComplete — encryption enabled, UID={uid}, PublicKeyLen={publicKeyDer?.Length}", ClientLogLevel.Debug);
            }
            else
            {
                /// <summary> Skips pipeline initialization when encryption is disabled </summary>
                EncryptionPipeline = null;
                ClientLogger.Log("MarkHandshakeComplete — encryption disabled, pipeline not initialized.", ClientLogLevel.Info);
            }
        }

        /// <summary>
        /// Background task that continuously reads framed packets until the connection closes.
        /// • Reads length‑prefixed payloads with PacketReader.
        /// • Dispatches roster and message updates to the UI thread.
        /// • Completes handshake when HandshakeAck is received.
        /// • Stops gracefully on cancellation, stream close, or protocol error.
        /// </summary>
        private async Task ReadPacketsAsync(CancellationToken cancellationToken)
        {
            /// <summary> Captures ViewModel reference on the UI thread </summary>
            MainViewModel viewModel = null!;

            /// <summary> Captures ViewModel without blocking the network read thread </summary>
            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow)
                {
                    viewModel = mainWindow.viewModel;
                }
            }).Task.ConfigureAwait(false);

            /// <summary> Ensures that ViewModel is available before proceeding </summary>
            if (viewModel == null)
            {
                return;
            }

            /// <summary> Waits for handshake reader to release lock before starting continuous read </summary>
            await _readerLock.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                /// <summary> Continuous read loop: runs until cancellation or disconnect </summary>
                while (!cancellationToken.IsCancellationRequested)
                {
                    /// <summary> Checks that TCP client is connected before reading </summary>
                    if (_tcpClient == null || !_tcpClient.Connected)
                    {
                        ClientLogger.Log("ReadPackets: socket not connected, exiting.", ClientLogLevel.Info);
                        break;
                    }

                    byte[] framedBody;

                    try
                    {
                        /// <summary> Reads next framed body via shared PacketReader </summary>
                        framedBody = await _packetReader!.ReadFramedBodyAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        /// <summary> Exits gracefully when cancellation is requested </summary>
                        break;
                    }
                    catch (IOException ioex)
                    {
                        /// <summary> Logs I/O error (remote closed, network glitch) and exits gracefully </summary>
                        ClientLogger.Log($"ReadPackets I/O error: {ioex.Message}", ClientLogLevel.Info);
                        break;
                    }
                    catch (SocketException sex)
                    {
                        /// <summary> Logs socket error and exits gracefully </summary>
                        ClientLogger.Log($"ReadPackets socket error: {sex.Message}", ClientLogLevel.Warn);
                        break;
                    }

                    /// <summary> Validates that framed body is present </summary>
                    if (framedBody == null || framedBody.Length == 0)
                    {
                        ClientLogger.Log("ReadPackets: remote closed stream or empty frame", ClientLogLevel.Info);
                        break;
                    }

                    try
                    {
                        /// <summary> Parses frame in-memory to avoid touching NetworkStream directly </summary>
                        using var ms = new MemoryStream(framedBody, writable: false);
                        var reader = new PacketReader(ms);

                        /// <summary> Reads opcode byte from framed payload </summary>
                        byte opcodeByte = await reader.ReadByteAsync(cancellationToken).ConfigureAwait(false);
                        var opcode = (PacketOpCode)opcodeByte;
                        ClientLogger.Log($"RECEIVED_PACKET_OPCODE={(byte)opcode}", ClientLogLevel.Debug);

                        switch (opcode)
                        {
                            case PacketOpCode.RosterBroadcast:
                                /// <summary> Resets unexpected-opcode counter </summary>
                                if (_consecutiveUnexpectedOpcodes != 0)
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                /// <summary> Reads roster count and entries </summary>
                                int totalUsers = await reader.ReadInt32NetworkOrderAsync(cancellationToken).ConfigureAwait(false);

                                var rosterEntries = new List<(Guid UserId, string Username, byte[] PublicKeyDer)>(totalUsers);
                                for (int i = 0; i < totalUsers; i++)
                                {
                                    Guid userId = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    string username = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);
                                    byte[] publicKeyDer = await reader.ReadBytesWithLengthAsync(64 * 1024, cancellationToken).ConfigureAwait(false);
                                    rosterEntries.Add((userId, username, publicKeyDer));
                                }

                                viewModel.UserHasClickedOnDisconnect = false;

                                /// <summary> Posts roster snapshot update to UI thread </summary>
                                _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                                {
                                    viewModel.DisplayRosterSnapshot(rosterEntries);
                                }));
                                break;

                            case PacketOpCode.HandshakeAck:
                                /// <summary> Signals handshake completion </summary>
                                _handshakeCompletionTcs?.TrySetResult(true);
                                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                /// <summary>
                                /// Sends public key once after ACK only if encryption was enabled at connect
                                /// and there is at least one peer. Prevents unsolicited publish in solo.
                                /// </summary>
                                if (EncryptionHelper.IsEncryptionActive && !_hasSentPublicKey && _viewModel.Users.Count > 1)
                                {
                                    await SendPublicKeyToServerAsync(LocalUid, EncryptionHelper.PublicKeyDer, 
                                        LocalUid, cancellationToken).ConfigureAwait(false);

                                    _hasSentPublicKey = true;
                                    ClientLogger.Log("Public key sent once after ACK (multi-client).", ClientLogLevel.Debug);
                                }

                                break;

                            case PacketOpCode.PlainMessage:
                                /// <summary> Resets unexpected-opcode counter </summary>
                                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                /// <summary> Reads sender UID and discards recipient placeholder </summary>
                                Guid senderUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                string message = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                /// <summary> Resolves sender name or falls back to UID string </summary>
                                string senderName = viewModel.Users.FirstOrDefault(u => u.UID == senderUid)?.Username ?? senderUid.ToString();

                                /// <summary> Posts plain message to UI thread </summary>
                                _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                                {
                                    viewModel.OnPlainMessageReceived(senderName, message);
                                }));
                                break;

                            case PacketOpCode.EncryptedMessage:
                                {
                                    /// <summary> Resets unexpected-opcode counter. </summary>
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    /// <summary> Reads sender UID and discards recipient UID. </summary>
                                    Guid encryptedSenderUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    /// <summary> Reads ciphertext payload. </summary>
                                    byte[] cipherBytes = await reader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);

                                    /// <summary> Validates ciphertext presence. </summary>
                                    if (cipherBytes == null || cipherBytes.Length == 0)
                                    {
                                        ClientLogger.Log("Encrypted payload empty; dropping.", ClientLogLevel.Warn);
                                        break;
                                    }

                                    /// <summary> Posts encrypted message reception to UI thread for centralized handling. </summary>
                                    _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                                    {
                                        _viewModel.OnEncryptedMessageReceived(encryptedSenderUid, cipherBytes);
                                    }));

                                    break;
                                }

                            case PacketOpCode.PublicKeyRequest:
                                {
                                    Guid first = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    Guid second = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    // Compares with LocalUid (network identity)
                                    Guid requesterUid = (first == LocalUid) ? second : first;

                                    var localKey = viewModel.LocalUser.PublicKeyDer ?? EncryptionHelper.PublicKeyDer;

                                    if (localKey?.Length > 0)
                                    {
                                        // Sends our public key using LocalUid (network identity)
                                        await SendPublicKeyToServerAsync(LocalUid, localKey,
                                            requesterUid, cancellationToken).ConfigureAwait(false);
                                    }
                                    else
                                    {
                                        ClientLogger.Log("PublicKeyRequest ignored (no local key available).", ClientLogLevel.Debug);
                                    }

                                    break;
                                }

                            case PacketOpCode.PublicKeyResponse:
                                {
                                    /// <summary>
                                    /// Resets the consecutive unexpected-opcode counter.
                                    /// This ensures that the connection does not mistakenly
                                    /// interpret valid packets as protocol errors.
                                    /// </summary>
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    /// <summary>
                                    /// Reads the origin UID (the peer who owns the key),
                                    /// followed by the DER-encoded public key bytes,
                                    /// and finally the requester UID (ignored in this context).
                                    /// </summary>
                                    Guid originUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    byte[] publickeyDer = await reader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    /// <summary>
                                    /// Updates the KnownPublicKeys dictionary with the received key
                                    /// and triggers a refresh of the encryption state via the ViewModel.
                                    /// This ensures that the local pipeline is aware of new or updated keys
                                    /// and can re-evaluate readiness for encrypted communication.
                                    /// </summary>
                                    _ = Application.Current.Dispatcher.BeginInvoke(() =>
                                    {
                                        /// <summary>
                                        /// Thread-safe update of KnownPublicKeys.
                                        /// Locks the dictionary to prevent concurrent modifications.
                                        /// </summary>
                                        lock (KnownPublicKeys)
                                        {
                                            KnownPublicKeys[originUid] = publickeyDer;
                                        }

                                        /// <summary> Invokes the ViewModel handler to process the new key. </summary>
                                        viewModel.OnPublicKeyReceived(originUid, publickeyDer);

                                        /// <summary> Logs the registration or update of the public key for traceability. </summary>
                                        ClientLogger.Log($"Registered/updated public key for {originUid}", ClientLogLevel.Info);
                                    });

                                    /// <summary> Breaks out of the switch-case after handling the PublicKeyResponse </summary>
                                    break;
                                }

                            case PacketOpCode.DisconnectNotify:
                                /// <summary>
                                /// Resets the unexpected-opcode counter to zero.
                                /// Ensures that a valid disconnect notification does not count as protocol noise.
                                /// </summary>
                                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                /// <summary>
                                /// Reads the UID and username of the disconnecting client from the stream.
                                /// </summary>
                                Guid discUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                string discName = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                /// <summary>
                                /// Posts a disconnect notification to the UI thread so that the view model
                                /// can remove the user from the list and update bindings.
                                /// </summary>
                                _ = Application.Current.Dispatcher.BeginInvoke(() => viewModel.OnUserDisconnected(discUid, discName));
                                break;

                            case PacketOpCode.ForceDisconnectClient:
                                /// <summary>
                                /// Posts a forced disconnect to the UI thread and exits the loop.
                                /// </summary>
                                _ = Application.Current.Dispatcher.BeginInvoke(() =>
                                {
                                    viewModel.OnDisconnectedByServer();
                                });
                                return;

                            default:

                                ClientLogger.Log($"Unexpected opcode 0x{opcodeByte:X2} in framed packet", ClientLogLevel.Warn);

                                /// <summary>
                                /// Disconnects gracefully if the threshold of unexpected opcodes is reached.
                                /// Calls OnDisconnectedByServer only if the disconnect was not user-initiated.
                                /// </summary>
                                if (Interlocked.Increment(ref _consecutiveUnexpectedOpcodes) >= 3)
                                {
                                    ClientLogger.Log("Too many consecutive unexpected opcodes, initiating graceful disconnect.", ClientLogLevel.Warn);
                                    _ = Application.Current.Dispatcher.BeginInvoke(() =>
                                    {
                                      
                                        viewModel.OnDisconnectedByServer();
                                      
                                    });
                                    return;
                                }
                                break;
                        }
                    }
                    catch (InvalidDataException ide)
                    {
                        /// <summary> Logs protocol-level error and exits loop </summary>
                        ClientLogger.Log($"ReadPackets protocol error: {ide.Message}", ClientLogLevel.Warn);
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        /// <summary> Exits gracefully on cancellation during parsing </summary>
                        break;
                    }
                    catch (Exception ex)
                    {
                        /// <summary> Logs non-fatal processing error and continues loop </summary>
                        ClientLogger.Log($"ReadPackets processing error: {ex.Message}", ClientLogLevel.Warn);
                        // Continue loop without crashing; tolerate unexpected payloads
                    }
                }
            }
            catch (Exception ex)
            {
                /// <summary> Logs fatal error in reader loop </summary>
                ClientLogger.Log($"ReadPackets fatal error: {ex.Message}", ClientLogLevel.Error);
            }
            finally
            {
                try 
                {
                    _readerLock.Release(); 
                } 

                catch { }

                try
                {
                    _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                    {
                        // Do not notify the ViewModel if the user clicked Disconnect
                        if (!viewModel.UserHasClickedOnDisconnect)
                        {
                            viewModel.OnDisconnectedByServer();
                        }
                    }));
                }

                catch { }

                try 
                { 
                    CleanConnection(); 
                } 
                
                catch { }

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
                packetBuilder.WriteOpCode((byte)PacketOpCode.PublicKeyRequest);
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
                builder.WriteOpCode((byte)PacketOpCode.DisconnectNotify);
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
        /// Sends a framed payload (length-prefixed) asynchronously over the TCP connection.
        /// Ensures serialized writes with a lock to prevent interleaving.
        /// Validates the stream before writing and handles cancellation or I/O errors gracefully.
        /// Returns true on success, false if the connection is invalid or an error occurs.
        /// </summary>
        private async Task<bool> SendFramedAsync(byte[] payload, CancellationToken cancellationToken)
        {
            /// <summary> Normalizes null payloads to empty array </summary>
            if (payload == null)
            {
                payload = Array.Empty<byte>();
            }

            /// <summary> Adds length prefix framing so the receiver can read length then payload </summary>
            var framed = Framing.Frame(payload);

            /// <summary> Acquires write lock to serialize concurrent sends </summary>
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                /// <summary> Captures the NetworkStream and validates it is writable </summary>
                var stream = _tcpClient.GetStream();

                if (stream is null || !stream.CanWrite)
                {
                    ClientLogger.Log("SendFramedAsync aborted — NetworkStream not writable.", ClientLogLevel.Error);
                    return false;
                }

                /// <summary> Writes framed bytes asynchronously </summary>
                await stream.WriteAsync(framed, 0, framed.Length, cancellationToken).ConfigureAwait(false);

                ClientLogger.Log($"SendFramedAsync: wrote {framed.Length} bytes.", ClientLogLevel.Debug);
                return true;
            }
            catch (OperationCanceledException)
            {
                /// <summary> Propagates cancellation to caller </summary>
                ClientLogger.Log("SendFramedAsync cancelled.", ClientLogLevel.Debug);
                throw;
            }
            catch (ObjectDisposedException ex)
            {
                /// <summary> Stream disposed during write — log and return false </summary>
                ClientLogger.Log($"SendFramedAsync failed — stream disposed: {ex.Message}", ClientLogLevel.Warn);
                return false;
            }
            catch (IOException ex)
            {
                /// <summary> I/O error (happens when remote closed) — logs and return false </summary>
                ClientLogger.Log($"SendFramedAsync failed — I/O error: {ex.Message}", ClientLogLevel.Warn);
                return false;
            }
            finally
            {
                /// <summary> Always release the write lock </summary>
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
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None); // cancel on invalid input
                return false;
            }

            if (_tcpClient == null || !_tcpClient.Connected)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync failed: socket not connected.", ClientLogLevel.Error);
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None); // cancel on no socket
                return false;
            }

            if (uid == Guid.Empty)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync failed: UID is empty.", ClientLogLevel.Error);
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None); // cancel on invalid uid
                return false;
            }

            if (publicKeyDer == null)
            {
                ClientLogger.Log("SendInitialConnectionPacketAsync failed: publicKeyDer is null.", ClientLogLevel.Error);
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None); // cancel on invalid public key
                return false;
            }

            try
            {
                // Builds the payload: opcode + username + uid + length-prefixed public key.
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)PacketOpCode.Handshake);
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
                        _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None); // cancel on empty frame
                        return false;
                    }

                    // First byte of frame payload is the opcode.
                    byte receivedOpcode = frame[0];
                    ClientLogger.Log($"RECEIVED_PACKET_OPCODE={receivedOpcode}", ClientLogLevel.Debug);

                    if (receivedOpcode != (byte)PacketOpCode.HandshakeAck)
                    {
                        ClientLogger.Log($"Unexpected packet opcode while waiting for HandshakeAck: {receivedOpcode}", ClientLogLevel.Error);
                        _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None); // cancel on unexpected opcode
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
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None); // cancel on cancellation
                return false;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"SendInitialConnectionPacketAsync exception: {ex.Message}", ClientLogLevel.Error);
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None); // cancel on unexpected exception
                return false;
            }
        }

        /// <summary>
        /// Sends a chat message to the server.
        /// Chooses plain or encrypted transmission depending on pipeline readiness.
        /// Broadcasts to peers or loops back in solo mode.
        /// </summary>
        /// <param name="plainText">The plaintext message to send.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        /// <returns>True if at least one packet was sent.</returns>
        public async Task<bool> SendMessageAsync(string plainText, CancellationToken cancellationToken)
        {
            /// <summary> Validates input and local user presence. </summary>
            if (string.IsNullOrWhiteSpace(plainText) || _viewModel?.LocalUser == null)
                return false;

            Guid senderUid = _viewModel.LocalUser.UID;
            
            /// <summary> Collects all users except the sender as recipients. </summary>
            var recipients = _viewModel.Users.Where(u => u.UID != senderUid).ToList();
            bool isEncryptionReady = (_viewModel?.EncryptionPipeline?.IsEncryptionReady == true);
            bool messageSent = false;

            /// <summary> Multi-recipient mode. </summary>
            foreach (var recipient in recipients)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var plainPacket = new PacketBuilder();

                if (!isEncryptionReady)
                {
                    /// <summary> Plain packet with sender UID and text. </summary>
                    plainPacket.WriteOpCode((byte)PacketOpCode.PlainMessage);
                    plainPacket.WriteUid(senderUid);
                    plainPacket.WriteString(plainText);
                }
                else if (KnownPublicKeys.TryGetValue(recipient.UID, out var pubKey) && pubKey?.Length > 0)
                {
                    /// <summary> Encrypt with recipient's public key. </summary>
                    var cipher = EncryptionHelper.EncryptMessageToBytes(plainText, pubKey);
                    if (cipher == null || cipher.Length == 0) continue;

                    plainPacket.WriteOpCode((byte)PacketOpCode.EncryptedMessage);
                    plainPacket.WriteUid(senderUid);
                    plainPacket.WriteUid(recipient.UID);
                    plainPacket.WriteBytesWithLength(cipher);
                }
                else
                {
                    ClientLogger.Log($"Missing public key for {recipient.UID}", ClientLogLevel.Warn);
                    continue;
                }

                await SendFramedAsync(plainPacket.GetPacketBytes(), cancellationToken).ConfigureAwait(false);
                messageSent = true;
            }

            /// <summary>
            /// Also send a self-copy encrypted with sender's own public key,
            /// so local echo can be decrypted.
            /// </summary>
            if (isEncryptionReady && _viewModel?.LocalUser.PublicKeyDer?.Length > 0)
            {
                var selfCipher = EncryptionHelper.EncryptMessageToBytes(plainText, _viewModel.LocalUser.PublicKeyDer);
                if (selfCipher != null && selfCipher.Length > 0)
                {
                    var selfPacket = new PacketBuilder();
                    selfPacket.WriteOpCode((byte)PacketOpCode.EncryptedMessage);
                    selfPacket.WriteUid(senderUid);
                    selfPacket.WriteUid(senderUid);
                    selfPacket.WriteBytesWithLength(selfCipher);

                    await SendFramedAsync(selfPacket.GetPacketBytes(), cancellationToken).ConfigureAwait(false);
                    messageSent = true;
                }
            }

            /// <summary> Solo mode (loopback). </summary>
            if (recipients.Count == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var encryptedPacket = new PacketBuilder();

                if (!isEncryptionReady)
                {
                    encryptedPacket.WriteOpCode((byte)PacketOpCode.PlainMessage);
                    encryptedPacket.WriteUid(senderUid);
                    encryptedPacket.WriteString(plainText);
                }
                else if (_viewModel?.LocalUser.PublicKeyDer?.Length > 0)
                {
                    var cipher = EncryptionHelper.EncryptMessageToBytes(plainText, _viewModel.LocalUser.PublicKeyDer);
                    if (cipher == null || cipher.Length == 0) return false;

                    encryptedPacket.WriteOpCode((byte)PacketOpCode.EncryptedMessage);
                    encryptedPacket.WriteUid(senderUid);
                    encryptedPacket.WriteUid(senderUid);
                    encryptedPacket.WriteBytesWithLength(cipher);
                }
                else return false;

                await SendFramedAsync(encryptedPacket.GetPacketBytes(), cancellationToken).ConfigureAwait(false);
                messageSent = true;
            }

            return messageSent;
        }

        /// <summary>
        /// Sends the local client's public RSA key to the server for distribution.
        /// This method ensures that the key is properly framed, transmitted, and logged.
        /// It also triggers a re-evaluation of encryption readiness, but readiness will only be true
        /// once all peer keys have been received (multi-user mode).
        /// • Validates connection before attempting to send.  
        /// • Normalizes payload (empty array means "clear mode").  
        /// • Builds a packet with opcode, origin UID, DER key, and requester UID.  
        /// • Sends the packet via the unified framed sender.  
        /// • Logs success or failure for traceability.  
        /// • Calls ReevaluateEncryptionStateFromConnection to refresh readiness/UI.  
        /// • Returns true if the send succeeded, false otherwise.  
        /// </summary>
        public async Task<bool> SendPublicKeyToServerAsync(Guid senderUid, byte[] publicKeyDer, Guid requesterUid, CancellationToken cancellationToken)
        {
            /// <summary>
            /// Validates that the TCP client is connected before proceeding.
            /// Prevents attempts to send when the connection is not established.
            /// </summary>
            if (_tcpClient?.Client == null || !_tcpClient.Connected)
            {
                ClientLogger.Log("Cannot send public key — client is not connected.", ClientLogLevel.Error);
                return false;
            }

            try
            {
                if (publicKeyDer == null || publicKeyDer.Length == 0)
                {
                    ClientLogger.Log("PublicKeyResponse not sent — empty key payload is not allowed.", ClientLogLevel.Warn);
                    return false;
                }

                var payloadKey = publicKeyDer;

                /// <summary>
                /// Builds the packet with required fields:
                /// - Opcode (PublicKeyResponse)
                /// - Origin UID (owner of the key)
                /// - DER-encoded public key
                /// - Requester UID (peer or self)
                /// </summary>
                var publicKeyPacket = new PacketBuilder();
                publicKeyPacket.WriteOpCode((byte)PacketOpCode.PublicKeyResponse);
                publicKeyPacket.WriteUid(senderUid);
                publicKeyPacket.WriteBytesWithLength(payloadKey);
                publicKeyPacket.WriteUid(requesterUid);

                ClientLogger.Log($"Sending public key — origin={senderUid}, requester={requesterUid}, Key length={payloadKey.Length}", ClientLogLevel.Debug);

                /// <summary> Sends the raw payload via unified sender. </summary>
                await SendFramedAsync(publicKeyPacket.GetPacketBytes(), cancellationToken).ConfigureAwait(false);

                ClientLogger.Log("Public key packet sent successfully.", ClientLogLevel.Debug);

                /// <summary>
                /// Re-evaluates encryption readiness immediately after sending key.
                /// Readiness will only be true if all peer keys are present.
                /// This prevents premature "ready" state in multi-user scenarios.
                /// </summary>
                _viewModel?.ReevaluateEncryptionStateFromConnection();

                return true;
            }
            catch (OperationCanceledException)
            {
                /// <summary> Propagates cancellation to caller. </summary>
                throw;
            }
            catch (Exception ex)
            {
                /// <summary>
                /// Logs any exception that occurs during send.
                /// Returns false to indicate failure.
                /// </summary>
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
                builder.WriteOpCode((byte)PacketOpCode.PublicKeyRequest);
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
