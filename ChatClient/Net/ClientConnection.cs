/// <file>ClientConnection.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 21th, 2026</date>

using ChatClient.Helpers;
using ChatClient.MVVM.Model;
using ChatClient.MVVM.View;
using ChatClient.MVVM.ViewModel;
using ChatClient.Properties;
using ChatProtocol.Net;
using ChatProtocol.Net.IO;
using System.Collections.ObjectModel;
using System.IO;
using System.Net.Sockets;
using System.Windows;

namespace ChatClient.Net
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
        /// Reference to the main ViewModel (always non-null).
        /// </summary>
        private static MainViewModel _viewModel = new MainViewModel();

        /// <summary>
        /// Callback used to run actions on the UI thread, ensuring safe property updates.
        /// </summary>
        private readonly Action<Action> _uiDispatcherInvoke;

        // Single-writer guard for this connection instance; kept readonly for the connection lifetime.
        private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);

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
        
        /// <summary>
        /// Initializes a new ClientConnection instance.
        /// Provides a callback that ensures the given action is executed on the UI thread,
        /// allowing ClientConnection to update UI-bound data safely from background threads.
        /// </summary>
        /// <param name="uiDispatcherInvoke">UI dispatcher callback provided by MainViewModel.</param>
        /// <param name="viewModel">Main ViewModel instance bound to the application.</param>
        public ClientConnection(Action<Action> uiDispatcherInvoke, MainViewModel viewModel)
        {
            _tcpClient = new TcpClient();
            LocalUid = Guid.Empty;
            LocalPublicKey = Array.Empty<byte>();
            
            _uiDispatcherInvoke = uiDispatcherInvoke ?? throw new ArgumentNullException(nameof(uiDispatcherInvoke));

            // Resolves the ViewModel from the injected parameter,
            // then the MainWindow DataContext or the existing static fallback
            _viewModel = viewModel ?? Application.Current?.MainWindow?.DataContext as MainViewModel ?? _viewModel
                ?? throw new InvalidOperationException("MainViewModel is required.");

            _viewModel.ResetEncryptionPipelineAndUI();
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
            // Resets handshake and encryption flags for a fresh state.
            _viewModel.ResetEncryptionPipelineAndUI();
            Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

            // Cancels handshake TCS to wake any awaiters.
            _handshakeCompletionTcs?.TrySetCanceled();
            _handshakeCompletionTcs = null;

            // Cancels and disposes connection CTS to stop read loop.
            _connectionCts?.Cancel();
            _connectionCts?.Dispose();
            _connectionCts = null;

            // Disposes TcpClient safely.
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
                // Reinitializes a fresh socket.
                _tcpClient = new TcpClient();
            }

            // Clears PacketReader reference (not IDisposable).
            _packetReader = null!;

            // Disposes and recreates the reader lock semaphore.
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
                // Closes/disposes any previous socket to ensure a clean start.
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

                // Creates a fresh TCP client instance.
                _tcpClient = new TcpClient();

                // Resolves target IP; falls back to loopback if missing.
                string ipToConnect = string.IsNullOrWhiteSpace(ipAddressOfServer) ? "127.0.0.1" : ipAddressOfServer;

                // Validates non-loopback IP format to avoid runtime parse errors.
                if (ipToConnect != "127.0.0.1" && !System.Net.IPAddress.TryParse(ipToConnect, out _))
                {
                    throw new ArgumentException(LocalizationManager.GetString("IPAddressInvalid"));
                }

                // Selects port from settings.
                int port = Settings.Default.PortNumber;

                // Opens the TCP connection asynchronously.
                await _tcpClient.ConnectAsync(ipToConnect, port).ConfigureAwait(false);
                ClientLogger.Log($"TCP connection established — IP: {ipToConnect}, Port: {port}", ClientLogLevel.Debug);

                // Binds a new PacketReader to the active network stream.
                _packetReader = new PacketReader(_tcpClient.GetStream());

                // Ensures a lock to serialize critical read sections.
                if (_readerLock == null)
                {
                    _readerLock = new SemaphoreSlim(1, 1);
                }

                // Generates a per-session UID that becomes the canonical ID on the server.
                LocalUid = Guid.NewGuid();

                // Initializes public key for handshake (real if encryption enabled, dummy otherwise).
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
                    // Uses a dummy but valid DER key to satisfy handshake format.
                    LocalPublicKey = EncryptionHelper.PublicKeyDer;
                }

                // Creates a handshake completion TCS to coordinate readiness.
                _handshakeCompletionTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

                // Sends initial handshake and awaits server ACK.
                bool handshakeConfirmed = await SendInitialConnectionPacketAsync(username, LocalUid, LocalPublicKey, cancellationToken)
                    .ConfigureAwait(false);
                if (!handshakeConfirmed)
                {
                    ClientLogger.LogLocalized(LocalizationManager.GetString("ErrorFailedToSendInitialHandshake"), ClientLogLevel.Error);

                    // Cleans up connection state on handshake failure.
                    CleanConnection();

                    // Cancels and releases handshake TCS to avoid hanging tasks.
                    _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None);
                    _handshakeCompletionTcs = null;

                    // Returns sentinel values to signal failure to caller.
                    return (Guid.Empty, Array.Empty<byte>());
                }

                // Completes handshake and delegates pipeline readiness.
                MarkHandshakeComplete(LocalUid, LocalPublicKey);

                // Notifies subscribers that the connection is established.
                ConnectionEstablished?.Invoke();

                // Starts background packet reading with a dedicated cancellation token.
                _connectionCts = new CancellationTokenSource();
                _ = Task.Run(() => ReadPacketsAsync(_connectionCts.Token), _connectionCts.Token);

                // Returns the established UID and public key to the caller.
                return (LocalUid, LocalPublicKey);
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("Connection to server canceled", ClientLogLevel.Debug);

                CleanConnection();

                // Propagates cancellation to the handshake TCS and clears it.
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None);
                _handshakeCompletionTcs = null;

                // Returns sentinel values to indicate cancellation to the caller.
                return (Guid.Empty, Array.Empty<byte>());
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Connection to server failed: {ex.Message}", ClientLogLevel.Error);

                // Ensures a clean teardown on unexpected errors.
                CleanConnection();

                // Cancels and releases handshake TCS on failure.
                _handshakeCompletionTcs?.TrySetCanceled(CancellationToken.None);
                _handshakeCompletionTcs = null;

                // Returns sentinel values to indicate failure to the caller.
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
            // Ensures single concurrent execution by using Interlocked.Exchange
            // to set the sentinel _disconnectFromServerCalled to 1.
            // If the previous value was non-zero, another disconnect is already in progress,
            // so the method returns immediately with a completed Task.
            if (Interlocked.Exchange(ref _disconnectFromServerCalled, 1) != 0)
            {
                return Task.CompletedTask;
            }

            try
            {
                // Cancels background readers so they stop consuming the stream.
                // Disposes the CancellationTokenSource to release unmanaged resources.
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

                // Clears the PacketReader reference and closes the network stream
                // only if the TcpClient is still connected.
                // This avoids redundant close attempts on already-disconnected sockets.
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

                // Closes and disposes the TcpClient safely, but only if it was instantiated.
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

                // Resets the unexpected-opcode counter and notifies listeners
                // that the connection has been terminated.
                Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);
                ConnectionTerminated?.Invoke();
            }
            finally
            {
                // Allows future disconnect calls by resetting the sentinel,
                // and resets the encryption init flag for clean future sessions.
                Volatile.Write(ref _disconnectFromServerCalled, 0);
                Volatile.Write(ref _encryptionInitOnce, 0);
            }

            // Returns a completed Task to satisfy the Task-based API contract.
            return Task.CompletedTask;
        }

        /// <summary>
        /// Marks the client-side handshake as complete.
        /// Finalizes the handshake TaskCompletionSource and stores
        /// the local user's identifier and public key material.
        /// </summary>
        /// <param name="uid">Unique identifier assigned to the local user.</param>
        /// <param name="publicKeyDer">Public key in DER format for the local user.</param>
        public void MarkHandshakeComplete(Guid uid, byte[] publicKeyDer)
        {
            // Completes the handshake TaskCompletionSource safely.
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

            // Stores local UID and public key material.
            LocalUid = uid;
            LocalPublicKey = publicKeyDer;

            ClientLogger.Log($"Handshake complete — UID={uid}, PublicKeyLen={publicKeyDer?.Length}", ClientLogLevel.Debug);
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
            // Captures ViewModel reference on the UI thread.
            MainViewModel viewModel = null!;

            // Captures ViewModel without blocking the network read thread.
            await Application.Current.Dispatcher.BeginInvoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow)
                {
                    viewModel = mainWindow.viewModel;
                }
            }).Task.ConfigureAwait(false);

            // Ensures that ViewModel is available before proceeding.
            if (viewModel == null)
            {
                return;
            }

            // Waits for handshake reader to release lock before starting continuous read.
            await _readerLock.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                // Continuous read loop: runs until cancellation or disconnect.
                while (!cancellationToken.IsCancellationRequested)
                {
                    // Checks that TCP client is connected before reading.
                    if (_tcpClient == null || !_tcpClient.Connected)
                    {
                        ClientLogger.Log("ReadPackets: socket not connected, exiting.", ClientLogLevel.Info);
                        break;
                    }

                    byte[] framedBody;

                    try
                    {
                        // Reads next framed body via shared PacketReader.
                        framedBody = await _packetReader!.ReadFramedBodyAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        // Exits gracefully when cancellation is requested.
                        break;
                    }
                    catch (IOException ioex)
                    {
                        // Logs I/O error (remote closed, network glitch) and exits gracefully.
                        ClientLogger.Log($"ReadPackets I/O error: {ioex.Message}", ClientLogLevel.Info);
                        break;
                    }
                    catch (SocketException sex)
                    {
                        // Logs socket error and exits gracefully.
                        ClientLogger.Log($"ReadPackets socket error: {sex.Message}", ClientLogLevel.Warn);
                        break;
                    }

                    // Validates that framed body is present.
                    if (framedBody == null || framedBody.Length == 0)
                    {
                        ClientLogger.Log("ReadPackets: remote closed stream or empty frame", ClientLogLevel.Info);
                        break;
                    }

                    try
                    {
                        // Parses frame in-memory to avoid touching NetworkStream directly.
                        using var ms = new MemoryStream(framedBody, writable: false);
                        var reader = new PacketReader(ms);

                        // Reads opcode byte from framed payload.
                        byte opcodeByte = await reader.ReadByteAsync(cancellationToken).ConfigureAwait(false);
                        var opcode = (PacketOpCode)opcodeByte;
                        ClientLogger.Log($"RECEIVED_PACKET_OPCODE={(byte)opcode}", ClientLogLevel.Debug);

                        switch (opcode)
                        {
                            case PacketOpCode.RosterBroadcast:
                                {

                                    // Resets unexpected-opcode counter.
                                    if (_consecutiveUnexpectedOpcodes != 0)
                                        Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    // Reads roster count and entries.
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

                                    // Posts roster snapshot update to UI thread.
                                    _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                                    {
                                        viewModel.DisplayRosterSnapshot(rosterEntries);
                                    }));
                                    break;
                                }

                            case PacketOpCode.HandshakeAck:
                                {
                                    // Signals handshake completion.
                                    _handshakeCompletionTcs?.TrySetResult(true);
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    var localKey = viewModel.LocalUser.PublicKeyDer ?? EncryptionHelper.PublicKeyDer;

                                    if (localKey?.Length > 0)
                                    {
                                        // Sends our public key using LocalUid as network identity.
                                        // requesterUid = LocalUid (we are sending our own key to the server).
                                        await SendPublicKeyToServerAsync(LocalUid, localKey, LocalUid, cancellationToken)
                                            .ConfigureAwait(false);
                                    }
                                    else
                                    {
                                        ClientLogger.Log("PublicKeyRequest ignored (no local key available).", ClientLogLevel.Debug);
                                    }

                                    break;
                                }

                            case PacketOpCode.PlainMessage:
                                {

                                    // Resets unexpected-opcode counter.
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    // Reads sender UID and discards recipient placeholder.
                                    Guid senderUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    string message = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                    // Resolves sender name or falls back to UID string.
                                    string senderName = viewModel.Users.FirstOrDefault(u => u.UID == senderUid)?.Username ?? senderUid.ToString();

                                    // Posts plain message to UI thread.
                                    _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                                    {
                                        viewModel.OnPlainMessageReceived(senderName, message);
                                    }));
                                    break;
                                }
                            case PacketOpCode.EncryptedMessage:
                                {
                                    // Resets unexpected-opcode counter
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    // Reads sender UID and discards recipient UID
                                    Guid encryptedSenderUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    // Reads ciphertext payload
                                    byte[] cipherBytes = await reader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);

                                    // Validates ciphertext presence
                                    if (cipherBytes == null || cipherBytes.Length == 0)
                                    {
                                        ClientLogger.Log("Encrypted payload empty; dropping.", ClientLogLevel.Warn);
                                        break;
                                    }

                                    // Forwards encrypted messages to the ViewModel
                                    _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                                    {
                                        _viewModel.OnEncryptedMessageReceived(encryptedSenderUid, cipherBytes);
                                    }));

                                    break;
                                }

                            case PacketOpCode.PublicKeyRequest:
                                {
                                    // Reads the UID of the key owner (target) and the UID of the requester.
                                    Guid targetUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    Guid requesterUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    // Ignores the request if this client is not the key owner.
                                    if (targetUid != LocalUid)
                                    {
                                        break;
                                    }

                                    // Resolves the local public key from ViewModel or fallback
                                    var localKey = viewModel.LocalUser.PublicKeyDer ?? EncryptionHelper.PublicKeyDer;

                                    // Sends our public key back to the requester if available.
                                    if (localKey?.Length > 0)
                                    {
                                        await SendPublicKeyToServerAsync(LocalUid, localKey, requesterUid, 
                                            cancellationToken).ConfigureAwait(false);
                                    }

                                    break;
                                }


                            case PacketOpCode.PublicKeyResponse:
                                {
                                    // Resets the consecutive unexpected-opcode counter.
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    // Reads origin UID, public key DER, and requester UID (ignored).
                                    Guid originUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    byte[] publicKeyDer = await reader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    _ = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    // Updates KnownPublicKeys on the UI thread.
                                    _ = Application.Current.Dispatcher.BeginInvoke(() =>
                                    {
                                        var encryptionPipeline = _viewModel!.EncryptionPipeline;
                                        if (encryptionPipeline == null)
                                        {
                                            ClientLogger.Log("Encryption pipeline is null during PublicKeyResponse.", ClientLogLevel.Warn);
                                            return;
                                        }

                                        // Looks for an existing PublicKeyEntry for this peer
                                        var matchingEntry = encryptionPipeline.KnownPublicKeys
                                            .FirstOrDefault(e => e.UID == originUid);

                                        // Builds a short Base64 excerpt for UI display
                                        string computedExcerpt = Convert.ToBase64String(publicKeyDer);
                                        if (computedExcerpt.Length > 20)
                                            computedExcerpt = computedExcerpt.Substring(0, 20) + "....";

                                        if (matchingEntry != null)
                                        {
                                            // Updates existing entry in place
                                            matchingEntry.KeyExcerpt = computedExcerpt;
                                        }
                                        else
                                        {
                                            // Inserts new entry
                                            encryptionPipeline.KnownPublicKeys.Add(
                                                new PublicKeyEntry
                                                {
                                                    UID = originUid,
                                                    Username = _viewModel.Users.FirstOrDefault(u => u.UID == originUid)?.Username ?? "",
                                                    KeyExcerpt = computedExcerpt,
                                                }
                                            );
                                        }

                                        // Notifies the ViewModel (handles readiness logic)
                                        _viewModel.OnPublicKeyReceived(originUid, publicKeyDer);

                                        ClientLogger.Log($"Registered/updated public key for {originUid}", ClientLogLevel.Info);
                                    });

                                    break;
                                }

                            case PacketOpCode.DisconnectNotify:
                                {
                                    // Resets the unexpected-opcode counter to zero.
                                    // Ensures that a valid disconnect notification does not count as protocol noise.
                                    Volatile.Write(ref _consecutiveUnexpectedOpcodes, 0);

                                    // Reads the UID and username of the disconnecting client from the stream.
                                    Guid discUid = await reader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    string discName = await reader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                    // Posts a disconnect notification to the UI thread so that the view model
                                    // can remove the user from the list and update bindings.
                                    _ = Application.Current.Dispatcher.BeginInvoke(() => viewModel.OnUserDisconnected(discUid, discName));
                                    break;
                                }
                            case PacketOpCode.ForceDisconnectClient:
                                {
                                    // Posts a forced disconnect to the UI thread and exits the loop.
                                    _ = Application.Current.Dispatcher.BeginInvoke(() =>
                                    {
                                        viewModel.OnDisconnectedByServer();
                                    });
                                    return;
                                }

                            default:
                                {
                                    ClientLogger.Log($"Unexpected opcode 0x{opcodeByte:X2} in framed packet", ClientLogLevel.Warn);

                                    // Disconnects gracefully if the threshold of unexpected opcodes is reached.
                                    // Calls OnDisconnectedByServer only if the disconnect was not user-initiated.
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
                    }
                    catch (InvalidDataException ide)
                    {
                        ClientLogger.Log($"ReadPackets protocol error: {ide.Message}", ClientLogLevel.Warn);
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        // Exits gracefully on cancellation during parsing.
                        break;
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"ReadPackets processing error: {ex.Message}", ClientLogLevel.Warn);
                        // Continues loop without crashing; tolerates unexpected payloads
                    }
                }
            }
            catch (Exception ex)
            {
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
                        // Don't notify the ViewModel if the user clicked Disconnect button
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
        /// Sends the framed payload through this unified send routine.
        /// Avoids direct socket writes, removes race conditions, and serializes all outbound traffic.
        /// Returns true on success, false otherwise.
        /// </summary>
        private async Task<bool> SendFramedAsync(byte[] payload, CancellationToken cancellationToken)
        {
            // Normalizes null payloads to empty array.
            if (payload == null)
            {
                payload = Array.Empty<byte>();
            }

            // Adds length prefix framing so the receiver can read length then payload.
            var framed = Framing.Frame(payload);

            // Acquires write lock to serialize concurrent sends.
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                // Captures the NetworkStream and validates it is writable.
                var stream = _tcpClient.GetStream();

                if (stream is null || !stream.CanWrite)
                {
                    ClientLogger.Log("SendFramedAsync aborted — NetworkStream not writable.", ClientLogLevel.Error);
                    return false;
                }

                // Writes framed bytes asynchronously.
                await stream.WriteAsync(framed, 0, framed.Length, cancellationToken).ConfigureAwait(false);

                ClientLogger.Log($"SendFramedAsync: wrote {framed.Length} bytes.", ClientLogLevel.Debug);
                return true;
            }
            catch (OperationCanceledException)
            {
                // Propagates cancellation to caller.
                ClientLogger.Log("SendFramedAsync cancelled.", ClientLogLevel.Debug);
                throw;
            }
            catch (ObjectDisposedException ex)
            {
                // Stream disposed during write
                ClientLogger.Log($"SendFramedAsync failed — stream disposed: {ex.Message}", ClientLogLevel.Warn);
                return false;
            }
            catch (IOException ex)
            {
                // I/O error (happens when remote closed).
                ClientLogger.Log($"SendFramedAsync failed — I/O error: {ex.Message}", ClientLogLevel.Warn);
                return false;
            }
            finally
            {
                // Always release the write lock.
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

                // Writes header and payload atomically and flushes.
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
        public async Task<bool> SendMessageAsync(string plainText, CancellationToken cancellationToken)
        {
            // Validates input and local user presence.
            if (string.IsNullOrWhiteSpace(plainText) || (_viewModel?.LocalUser == null))
            {
                return false;
            }

            Guid senderUid = _viewModel.LocalUser.UID;

            // Collects all users except the sender as recipients.
            var recipients = _viewModel.Users.Where(u => u.UID != senderUid).ToList();

            bool isEncryptionReady = Settings.Default.UseEncryption &&
                _viewModel?.EncryptionPipeline?.IsEncryptionReady == true;

            bool messageSent = false;

            foreach (var recipient in recipients)
            {
                // Aborts early if the operation was cancelled
                cancellationToken.ThrowIfCancellationRequested();
                
                var packet = new PacketBuilder();

                if (!isEncryptionReady)
                {
                    // Builds plain packet with sender UID and text.
                    packet.WriteOpCode((byte)PacketOpCode.PlainMessage);
                    packet.WriteUid(senderUid);
                    packet.WriteString(plainText);
                }
                else
                {
                    var pipeline = _viewModel!.EncryptionPipeline;
                    
                    if (pipeline == null)
                    {
                        ClientLogger.Log("Encryption pipeline is null.", ClientLogLevel.Warn);
                        continue;
                    }

                    // Finds recipient entry by UID
                    var entry = pipeline.KnownPublicKeys
                        .FirstOrDefault(e => e.UID == recipient.UID);

                    byte[] recipientPublicKeyDer = recipient.PublicKeyDer;

                    if (recipientPublicKeyDer == null || recipientPublicKeyDer.Length == 0)
                    {
                        ClientLogger.Log($"Missing public key for {recipient.UID}", ClientLogLevel.Warn);
                        continue;
                    }

                    // Encrypts message with recipient's public key.
                    var cipher = EncryptionHelper.EncryptMessageToBytes(plainText, recipientPublicKeyDer);
                    if (cipher == null || cipher.Length == 0)
                    {
                        continue;
                    }

                    packet.WriteOpCode((byte)PacketOpCode.EncryptedMessage);
                    packet.WriteUid(senderUid);
                    packet.WriteUid(recipient.UID);
                    packet.WriteBytesWithLength(cipher);
                }

                // Sends the packet
                await SendFramedAsync(packet.GetPacketBytes(), cancellationToken).ConfigureAwait(false);
                messageSent = true;
            }

            // Sends a self-copy encrypted with sender's own public key (for local echo).
            if (isEncryptionReady && (_viewModel?.LocalUser.PublicKeyDer?.Length > 0))
            {
                byte[] selfCipher = EncryptionHelper.EncryptMessageToBytes(plainText, _viewModel.LocalUser.PublicKeyDer);

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

            // Solo mode (loopback).
            if (recipients.Count == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var loopPacket = new PacketBuilder();

                if (!isEncryptionReady)
                {
                    loopPacket.WriteOpCode((byte)PacketOpCode.PlainMessage);
                    loopPacket.WriteUid(senderUid);
                    loopPacket.WriteString(plainText);
                }
                else if (_viewModel?.LocalUser.PublicKeyDer?.Length > 0)
                {
                    var cipher = EncryptionHelper.EncryptMessageToBytes(plainText, _viewModel.LocalUser.PublicKeyDer);
                    if (cipher == null || cipher.Length == 0)
                        return false;

                    loopPacket.WriteOpCode((byte)PacketOpCode.EncryptedMessage);
                    loopPacket.WriteUid(senderUid);
                    loopPacket.WriteUid(senderUid);
                    loopPacket.WriteBytesWithLength(cipher);
                }
                else
                {
                    return false;
                }

                await SendFramedAsync(loopPacket.GetPacketBytes(), cancellationToken).ConfigureAwait(false);
                messageSent = true;
            }

            return messageSent;
        }


        /// <summary>
        /// Sends the local client's public RSA key to the server for distribution.
        /// Ensures proper framing and transmission.
        /// Also triggers a re-evaluation of encryption readiness, 
        /// which only becomes true once all peer keys have been received.
        /// 
        /// • Validates connection before sending  
        /// • Normalizes payload (empty array = invalid)  
        /// • Builds packet: opcode, origin UID, DER key, requester UID  
        /// • Sends via framed sender  
        /// • Re-evaluates encryption readiness  
        /// • Returns true on success, false otherwise  
        /// </summary>
        public async Task<bool> SendPublicKeyToServerAsync(Guid senderUid, byte[] publicKeyDer,
            Guid requesterUid, CancellationToken cancellationToken)
        {
            // Rejects invalid sender UID to avoid corrupting server-side roster mapping.
            if (senderUid == Guid.Empty)
            {
                ClientLogger.Log("Public key not sent — sender UID is empty (Guid.Empty).", ClientLogLevel.Warn);
                return false;
            }

            // Ensures the TCP client is connected before sending.
            if (_tcpClient?.Client == null || !_tcpClient.Connected)
            {
                ClientLogger.Log("Cannot send public key — client is not connected.", ClientLogLevel.Error);
                return false;
            }

            try
            {
                // Validates payload.
                if (publicKeyDer == null || publicKeyDer.Length == 0)
                {
                    ClientLogger.Log("PublicKeyResponse not sent — empty key payload is not allowed.", ClientLogLevel.Warn);
                    return false;
                }

                // Builds the packet:
                //   [OpCode][OriginUid][DER Key][RequesterUid]
                var builder = new PacketBuilder();
                builder.WriteOpCode((byte)PacketOpCode.PublicKeyResponse);
                builder.WriteUid(senderUid);
                builder.WriteBytesWithLength(publicKeyDer);
                builder.WriteUid(requesterUid);

                ClientLogger.Log($"Sending public key — origin={senderUid}, requester={requesterUid}, keyLength={publicKeyDer.Length}",
                    ClientLogLevel.Debug);

                // Sends the packet.
                await SendFramedAsync(builder.GetPacketBytes(), cancellationToken).ConfigureAwait(false);

                ClientLogger.Log("Public key packet sent successfully.", ClientLogLevel.Debug);

                _viewModel?.RefreshEncryptionState();

                return true;
            }
            catch (OperationCanceledException)
            {
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
                builder.WriteOpCode((byte)PacketOpCode.PublicKeyRequest);
                builder.WriteUid(LocalUid);
                builder.WriteUid(targetUid);

                byte[] payload = builder.GetPacketBytes();

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
