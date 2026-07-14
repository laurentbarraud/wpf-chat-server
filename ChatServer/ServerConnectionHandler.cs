/// <file>ServerConnectionHandler.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>July 15th, 2026</date>

using ChatProtocol.Net;
using ChatProtocol.Net.IO;
using ChatServer.Helpers;
using System;
using System.Net.Sockets;

namespace ChatServer
{
    /// <summary>
    /// Represents a connected client.
    /// Listens for framed packets, dispatches by opcode,
    /// and handles graceful disconnect.
    /// </summary>
    public class ServerConnectionHandler
    {
        // Public properties for the connected user

        public TcpClient ClientSocket { get; private set; } = null!;
        
        /// <summary>
        /// DateTime when the handshake was completed and the connection considered established.
        /// Used for "On since" display.
        /// </summary>
        public DateTime ConnectedSince { get; private set; } = DateTime.MinValue;
        
        /// <summary>
        /// Indicates whether the connection is fully established at the protocol level.
        /// A TCP socket being connected is not enough: the handshake must also be processed
        /// to ensure the client has identified itself and the session is properly initialized.
        /// </summary>
        public bool IsEstablished => ClientSocket?.Connected == true && _handshakeProcessed;
        public byte[] PublicKeyDer { get; private set; } = Array.Empty<byte>();
        public Guid UID { get; private set; } = Guid.Empty;
        public string Username { get; private set; } = string.Empty;

        // Private members for internal state management

        private int _cleanupState = 0;
        private int _closed = 0;
        private CancellationTokenSource? _connectionCts;
        private int _disconnectNotifySent = 0;
        private volatile bool _handshakeProcessed = false;
        private readonly PacketReader packetReader;
        private int _readerStarted = 0;

        // Constructor - initializes the connection handler with a TcpClient and sets up the packet reader.
        public ServerConnectionHandler(TcpClient client)
        {
            ClientSocket = client ?? throw new ArgumentNullException(nameof(client));
            packetReader = new PacketReader(ClientSocket.GetStream());
        }

        /// <summary>
        /// Cleans up the connection and removes the user from the global list.
        /// </summary>
        private void CleanupAfterDisconnect()
        {
            if (Interlocked.CompareExchange(ref _cleanupState, 1, 0) != 0)
            {
                return;
            }

            try
            {
                ServerConnectionHandler? myConnectionHandler;

                // Locks the global Users list to safely remove this user
                lock (Program.Users)
                {
                    myConnectionHandler = Program.Users.FirstOrDefault(user => user.UID == UID);

                    if (myConnectionHandler != null)
                    {
                        Program.Users.Remove(myConnectionHandler);
                    }
                }

                if (myConnectionHandler != null)
                {
                    string username = string.IsNullOrWhiteSpace(myConnectionHandler.Username)
                        ? "(unknown)"
                        : myConnectionHandler.Username;

                    // Broadcasts the disconnect notification to all other clients
                    _ = Program.BroadcastDisconnectNotify(myConnectionHandler.UID, username, CancellationToken.None);

                    ServerLogger.LogLocalized("ClientRemoved", ServerLogLevel.Info, username);
                }
                else
                {
                    ServerLogger.LogLocalized("ClientRemoved", ServerLogLevel.Info, Username ?? UID.ToString());
                }
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("CleanupFailed", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }
        }

        /// <summary>
        /// Returns a human-readable duration string since ConnectedSince.
        /// Example: "01h 02m 30s".
        /// </summary>
        public string GetConnectedSinceDurationString()
        {
            if (ConnectedSince == DateTime.MinValue)
            {
                return "unknown";
            }

            TimeSpan timeSpan = DateTime.UtcNow - ConnectedSince;
            int computedHours = (int)timeSpan.TotalHours;
            int computedMinutes = timeSpan.Minutes;
            int computedSeconds = timeSpan.Seconds;

            return $"{computedHours:00}h {computedMinutes:00}m {computedSeconds:00}s";
        }

        /// <summary>
        /// Initializes the connection after a successful handshake, setting the username, UID, and public key.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="uid"></param>
        /// <param name="publicKey"></param>
        /// <param name="serverToken">The cancellation token from the server to link with the connection's token.</param>
        internal void InitializeAfterHandshake(string username, Guid uid, byte[] publicKey, CancellationToken serverToken = default)
        {
            this.Username = username ?? string.Empty;
            this.UID = uid;
            PublicKeyDer = publicKey ?? Array.Empty<byte>();
            _handshakeProcessed = true;
            ConnectedSince = DateTime.UtcNow;

            try
            {
                _connectionCts?.Dispose();
            }
            catch { }

            // Create a linked cancellation token source that combines the server's token with this connection's token
            _connectionCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);

            // Start the packet reading loop in a background task if it hasn't already started
            if (Interlocked.CompareExchange(ref _readerStarted, 1, 0) == 0)
            {
                // Async Task.Run ensures packet processing never blocks accept loop.
                _ = Task.Run(() => ProcessReadPacketsAsync(_connectionCts.Token), _connectionCts.Token);
            }
        }

        /// <summary>
        /// Processes incoming framed packets in a loop until the connection is closed or an error occurs.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns>A Task representing the asynchronous operation.</returns>
        private async Task ProcessReadPacketsAsync(CancellationToken cancellationToken)
        {
            try
            {
                const int handshakeWaitTimeoutMs = 2000;

                // A stopwatch is used to enforce a timeout for the handshake process.
                // If the handshake is not completed within the specified time, the connection will be closed.
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                
                while (!_handshakeProcessed && stopwatch.ElapsedMilliseconds < handshakeWaitTimeoutMs)
                {
                    // await and yield means that we are not blocking the thread and allowing other tasks to run.
                    // This prevents infinite loops without await.
                    await Task.Yield();

                    // Checks for cancellation to exit early if the connection is being closed
                    if (cancellationToken.IsCancellationRequested)
                    {
                        ServerLogger.LogLocalized("HandshakeCancelledBeforePacketLoop", ServerLogLevel.Debug, Username);
                        TryCloseConnectionSafely(null);
                        return;
                    }
                }

                // If the handshake was not processed within the timeout, logs a warning and closes the connection
                if (!_handshakeProcessed)
                {
                    ServerLogger.LogLocalized("HandshakeTimeoutBeforePacketLoop", ServerLogLevel.Warn, Username);
                    TryCloseConnectionSafely(null);
                    return;
                }

                ServerLogger.LogLocalized("StartingPacketLoop", ServerLogLevel.Debug, Username);

                // This packet loop is fully async; no Thread.Sleep or synchronous blocking.
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (ClientSocket == null || !ClientSocket.Connected)
                    {
                        ServerLogger.LogLocalized("SocketNotConnected", ServerLogLevel.Info, Username);
                        break;
                    }

                    byte[] framedBody;

                    try
                    {
                        // ReadFramedBodyAsync waits asynchronously for data; no busy waiting or blocking.
                        framedBody = await packetReader.ReadFramedBodyAsync(cancellationToken).ConfigureAwait(false);
                    }
                    
                    catch (OperationCanceledException)
                    {
                        ServerLogger.LogLocalized("ReadCancelled", ServerLogLevel.Info, Username);
                        break;
                    }
                    
                    catch (InvalidDataException ide)
                    {
                        ServerLogger.LogLocalized("InvalidFrameLength", ServerLogLevel.Warn, Username, ide.Message);
                        break;
                    }
                    
                    catch (IOException)
                    {
                        ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
                        break;
                    }
                    
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("ReadPacketsProtocolError", ServerLogLevel.Warn, ex.Message);
                        break;
                    }

                    if (framedBody == null || framedBody.Length == 0)
                    {
                        ServerLogger.LogLocalized("EmptyFrame", ServerLogLevel.Warn, Username);
                        continue;
                    }

                    // Process the framed packet from a memory stream to avoid holding onto the original buffer longer than necessary.
                    // The using statement ensures the memory stream is disposed after processing.
                    // The PacketReader reads the opcode and dispatches to the appropriate handler based on the opcode.
                    try
                    {  
                        using var ms = new MemoryStream(framedBody);
                        var bodyReader = new PacketReader(ms);

                        // ConfigureAwait(false) is used to avoid capturing the synchronization context,
                        // This prevents deadlocks and improves performance in server applications where the context is not needed.
                        byte opcodeByte = await bodyReader.ReadByteAsync(cancellationToken).ConfigureAwait(false);
                        var opcode = (PacketOpCode)opcodeByte;

                        switch (opcode)
                        {
                            case PacketOpCode.RosterBroadcast:
                                await Program.BroadcastRosterAsync(cancellationToken).ConfigureAwait(false);
                                break;

                            case PacketOpCode.PublicKeyRequest:
                                {
                                    var requestSender = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var requestTarget = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    await Program.RelayPublicKeyRequest(requestSender, requestTarget, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case PacketOpCode.PublicKeyResponse:
                                {
                                    var requesterUserPublicKeyUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var publicKey = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    var publicKeyRequesterUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    var requesterUser = Program.Users.FirstOrDefault(user => user.UID == requesterUserPublicKeyUid);

                                    if (requesterUser != null)
                                    {
                                        requesterUser.PublicKeyDer = publicKey ?? Array.Empty<byte>();
                                        ServerLogger.Log($"Registered/updated public key for {requesterUser?.Username ?? "<unknown>"}", ServerLogLevel.Info);
                                    }
                                    
                                    else
                                    {
                                        ServerLogger.Log($"Origin user {requesterUserPublicKeyUid} not found in roster; proceeding to relay.", ServerLogLevel.Warn);
                                    }

                                    // Relays the public key to the requesting user and sends an empty array if the public key is null to avoid null reference issues.
                                    await Program.RelayPublicKeyToUser(requesterUserPublicKeyUid, publicKey ?? Array.Empty<byte>(),
                                        publicKeyRequesterUid, cancellationToken).ConfigureAwait(false);

                                    // Broadcasts the new public key to all connected clients, ensuring that even if the public key is null, an empty array is sent to avoid null reference issues.
                                    await Program.BroadcastNewPublicKeyAsync(requesterUserPublicKeyUid, publicKey ?? Array.Empty<byte>(), cancellationToken);

                                    break;
                                }

                            case PacketOpCode.PlainMessage:
                                {
                                    Guid senderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    string text = await bodyReader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                    ServerLogger.LogLocalized("MessageReceived", ServerLogLevel.Info, Username, text);

                                    await Program.BroadcastPlainMessage(text, senderUid, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case PacketOpCode.EncryptedMessage:
                                {
                                    Guid senderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    Guid recipientUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    byte[] ciphertext = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);

                                    if (ciphertext == null || ciphertext.Length == 0)
                                    {
                                        ServerLogger.LogLocalized("EncryptedPayloadEmpty", ServerLogLevel.Warn, Username);
                                        break;
                                    }

                                    string senderDisplayName = Program.Users.FirstOrDefault(user => user.UID == senderUid)?.Username ?? senderUid.ToString() ?? "Unknown user";
                                    string recipientDisplayName = Program.Users.FirstOrDefault(user => user.UID == recipientUid)?.Username ?? recipientUid.ToString() ?? "Unknown user";

                                    ServerLogger.LogLocalized("EncryptedMessageReceived", ServerLogLevel.Info, senderDisplayName, recipientDisplayName);

                                    // Async relay ensures encrypted messages do not block the main loop.
                                    await Program.RelayEncryptedMessageToAUser(ciphertext, senderUid, recipientUid, cancellationToken)
                                        .ConfigureAwait(false);

                                    break;
                                }

                            case PacketOpCode.DisconnectNotify:
                                {
                                    var disconnectedUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    // DisconnectNotify is broadcast only once; atomic guard prevents duplicates.
                                    // This line means: "If _disconnectNotifySent is 0, set it to 1 and return true;
                                    // otherwise, return false."
                                    if (Interlocked.CompareExchange(ref _disconnectNotifySent, 1, 0) == 0)
                                    {
                                        await Program.BroadcastDisconnectNotify(disconnectedUid, Username,
                                            cancellationToken).ConfigureAwait(false);
                                    }
                                    else
                                    {
                                        ServerLogger.LogLocalized("DisconnectNotifyAlreadySent", ServerLogLevel.Debug, Username, disconnectedUid.ToString());
                                    }
                                    break;
                                }

                            case PacketOpCode.Handshake:
                                {
                                    ServerLogger.LogLocalized("UnexpectedHandshake", ServerLogLevel.Warn, Username);
                                    break;
                                }

                            case PacketOpCode.ForceDisconnectClient:
                                {
                                    var targetUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    
                                    if (targetUid == UID)
                                    {
                                        ServerLogger.LogLocalized("ForceDisconnectReceived", ServerLogLevel.Info, Username);
                                        TryCloseConnectionSafely(null);
                                        return;
                                    }
                                    break;
                                }

                            default:
                                ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn, Username, $"{(byte)opcode}");
                                break;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        ServerLogger.LogLocalized("PacketProcessingCancelled", ServerLogLevel.Debug, Username);
                        break;
                    }
                    catch (Exception ex)
                    {
                        ServerLogger.LogLocalized("ErrorPacketLoop", ServerLogLevel.Error, Username, ex.ToString());
                        TryCloseConnectionSafely(ex);
                        break;
                    }
                }
            }
            
            catch (ObjectDisposedException)
            {
                ServerLogger.LogLocalized("StreamDisposed", ServerLogLevel.Info, Username);
            }
            
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorPacketLoop", ServerLogLevel.Error, Username, ex.ToString());
            }
            
            finally
            {
                try
                {
                    CleanupAfterDisconnect();
                }
                catch { }
            }
        }

        /// <summary>
        /// Performs a thread-safe one-time close of the connection and associated resources.
        /// Ensures multiple callers do not double-dispose sockets or duplicate cleanup actions.
        /// </summary>
        private void TryCloseConnectionSafely(Exception? ex = null)
        {
            // If the connection is already closed, exit early to avoid double cleanup.
            // This line means: "Atomically set _closed to 1 and check if it was already 1 before the exchange." 
            if (Interlocked.Exchange(ref _closed, 1) == 1)
            {
                return;
            }

            try
            {
                if (ex != null)
                {
                    ServerLogger.LogLocalized("ConnectionClosingDueToError", ServerLogLevel.Warn, Username, ex.Message);
                }

                try
                {
                    ClientSocket?.Close();
                }
                catch (Exception closeEx)
                {
                    ServerLogger.LogLocalized("SocketCloseFailed", ServerLogLevel.Debug, Username, closeEx.Message);
                }
            }
            finally
            {
            }
        }

        /// <summary>
        /// Called from Program to force-close this connection (kick/raus).
        /// </summary>
        internal void ForceCloseFromServer()
        {
            TryCloseConnectionSafely(null);
        }
    }
}
