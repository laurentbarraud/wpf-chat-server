/// <file>ServerConnectionHandler.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 12th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System;
using System.Net;
using System.Net.Sockets;


namespace chat_server
{
    /// <summary>
    /// Represents a connected client.
    /// Listens for framed packets, dispatches by opcode,
    /// and handles graceful disconnect.
    /// </summary>
    public class ServerConnectionHandler
    {
        /// <summary>
        /// The logged-in username for this connection.
        /// </summary>
        public string Username { get; private set; } = string.Empty;

        /// <summary>
        /// The unique identifier for this connection/client.
        /// </summary>
        public Guid UID { get; private set; }

        /// <summary>
        /// Underlying TcpClient representing the remote socket.
        /// </summary>
        public TcpClient ClientSocket { get; private set; } = null!;

        /// <summary>
        /// Client's public key in DER format.
        /// </summary>
        public byte[] PublicKeyDer { get; private set; } = Array.Empty<byte>();

        /// <summary>
        /// Reader that understands your framing protocol and exposes async read helpers.
        /// </summary>
        private readonly PacketReader packetReader;

        /// <summary>
        /// Cleanup state: 0 = not cleaned, 1 = cleaning or cleaned.
        /// </summary>
        private int _cleanupState = 0;

        /// <summary>
        /// Per-connection CancellationTokenSource used to cancel the read loop or shutdown this connection.
        /// </summary>
        private CancellationTokenSource? _connectionCts;

        /// <summary>
        /// Guard to ensure a single disconnect-notify is broadcast for this client.
        /// 0 = not sent, 1 = sent.
        /// </summary>
        private int _disconnectNotifySent = 0;

        ///<summary>
        /// Atomic flag used to ensure the per-client packet reader is started once.
        /// 0 = not started, 1 = started
        /// </summary>
        private int _readerStarted = 0;

        /// <summary>
        /// True when this client's handshake has been fully processed on the server side.
        /// Placed with other instance fields in Client.cs.
        /// Using volatile ensures reads/writes are immediately visible across threads 
        /// without heavier synchronization.
        /// </summary>
        private volatile bool _handshakeProcessed = false;

        // One-time close guard used by TryCloseConnectionSafely
        private int _closed = 0;

        /// <summary>
        /// • Accepts a connected TcpClient and assigns it to the connection object.
        /// • Wraps the client's network stream with a PacketReader for framed reads.
        /// </summary>
        /// <param name="client">Accepted TcpClient instance.</param>
        public ServerConnectionHandler(TcpClient client)
        {
            // Validates and assign the TcpClient reference.
            ClientSocket = client ?? throw new ArgumentNullException(nameof(client));

            // Assigns a provisional UID; final UID may be set after the asynchronous handshake.
            UID = Guid.NewGuid();

            // Creates a PacketReader over the underlying network stream for framed reads.
            // PacketReader is async-first.
            packetReader = new PacketReader(ClientSocket.GetStream());
        }

        /// <summary>
        /// Atomically runs the per-connection cleanup sequence exactly once.
        /// If the cleanup flag is 0 it is set to 1 and cleanup proceeds;
        /// if another thread already performed cleanup the method returns immediately.
        /// This prevents duplicated socket closes, duplicate broadcast notifications,
        /// and reentrancy-related exceptions.
        /// </summary>
        private void CleanupAfterDisconnect()
        {
            /// <summary>
            /// Attempts to set _cleanupState from 0 to 1.
            /// Syntax of Interlocked.CompareExchange :
            /// • ref _cleanupState: we pass the variable by reference, so the method can read and modify the value
            ///   directly.
            /// • 1: the new value we want to set if the condition is met
            /// • 0: the currently present expected value; the operation will only replace the value if the variable
            ///   is exactly 0.
            /// • method return: the old value that was in _cleanupState at the time of the call.
            ///   If the returned value is 0, it means that the caller was successful in replacing it with 1.
            ///   If the returned value is not 0, it means that another thread has already changed the value.
            ///   The test != 0 in the code therefore means: "if the previous value was not 0, we do nothing and we exit".
            /// </summary>
            if (Interlocked.CompareExchange(ref _cleanupState, 1, 0) != 0)
                return;

            // Requests cooperative cancellation of any running per-connection reader.
            try
            {
                try 
                { 
                    _connectionCts?.Cancel(); 
                } 
                catch { }
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorCancelConnectionCts", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            // Attempts to close the underlying socket.
            try
            {
                try 
                { 
                    ClientSocket?.Close(); 
                } 
                catch { }
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorClientCleanup", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            // Notifies remaining users about this disconnect (fire-and-forget).
            try
            {
                _ = Program.BroadcastDisconnectNotify(UID, CancellationToken.None);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorBroadcastDisconnectNotify", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            // Removes and disposes per-connection send semaphore to avoid leaks.
            try
            {
                Program.RemoveAndDisposeSendSemaphore(UID);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorClientCleanup", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            // Disposes the per-connection CTS after cancellation to release resources.
            try
            {
                try 
                { 
                    _connectionCts?.Dispose(); 
                } 
                catch { }
                
                _connectionCts = null;
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorDisposeConnectionCts", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            ServerLogger.LogLocalized("ClientCleanupComplete", ServerLogLevel.Info, Username ?? UID.ToString());
        }

        /// <summary>
        /// Finalizes a connection after an async handshake has been validated by the accept loop.
        /// • Sets handshake-derived properties (Username, UID, PublicKeyDer) and marks the handler ready.
        /// • Creates a per-connection CancellationTokenSource linked to the provided serverToken so the
        ///   read loop can be cancelled when the server shuts down or when the connection is closed.
        /// • Starts the per-connection read loop exactly once on the thread-pool, passing the linked token
        ///   so reads and dispatching observe cooperative cancellation.
        /// • Ensures any previous connection CTS is disposed to avoid resource leaks.
        /// </summary>

        internal void InitializeAfterHandshake(string username, Guid uid, byte[] publicKeyDer, CancellationToken serverToken = default)
        {
            // Populates handshake-derived state
            Username = username ?? string.Empty;
            UID = uid;
            PublicKeyDer = publicKeyDer ?? Array.Empty<byte>();
            _handshakeProcessed = true;

            // Disposes any existing per-connection CTS and create a new linked CTS with the server token.
            try 
            { 
                _connectionCts?.Dispose(); 
            } 
            catch { }

            _connectionCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);

            // Starts the per-connection packet loop exactly once
            if (Interlocked.CompareExchange(ref _readerStarted, 1, 0) == 0)
            {
                // Starts the cancellable reader on the thread pool and associates it with the CTS token.
                _ = Task.Run(() => ProcessReadPacketsAsync(_connectionCts.Token), _connectionCts.Token);
            }
        }

        /// <summary>
        /// Performs the per-connection read loop asynchronously.
        /// Reads framed bodies using PacketReader.ReadFramedBodyAsync and dispatches packets by opcode.
        /// Uses the supplied CancellationToken for cooperative cancellation (server shutdown / per-connection cancel).
        /// Ensures robust framing, length validation, and centralized error handling and cleanup.
        /// </summary>
        /// <param name="cancellationToken">Token to cancel the per-connection read loop.</param>
        private async Task ProcessReadPacketsAsync(CancellationToken cancellationToken)
        {
            try
            {
                // Wait briefly for the accept loop to mark the handshake as processed.
                const int handshakeWaitTimeoutMs = 2000;
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                while (!_handshakeProcessed && stopwatch.ElapsedMilliseconds < handshakeWaitTimeoutMs)
                {
                    // Yield to avoid busy-waiting and let cancellation be observed.
                    await Task.Yield();

                    if (cancellationToken.IsCancellationRequested)
                    {
                        // Server requested cancellation before handshake completed.
                        ServerLogger.LogLocalized("HandshakeCancelledBeforePacketLoop", ServerLogLevel.Debug, Username);
                        TryCloseConnectionSafely(null);
                        return;
                    }
                }

                if (!_handshakeProcessed)
                {
                    // Handshake didn't complete in time — defensive close to avoid protocol desync.
                    ServerLogger.LogLocalized("HandshakeTimeoutBeforePacketLoop", ServerLogLevel.Warn, Username);
                    TryCloseConnectionSafely(null);
                    return;
                }

                ServerLogger.LogLocalized("StartingPacketLoop", ServerLogLevel.Debug, Username);

                // Main read loop: run until socket disconnected, cancellation requested, or fatal error.
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
                        // Reads one framed body atomically; propagates cancellation.
                        framedBody = await packetReader.ReadFramedBodyAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        ServerLogger.LogLocalized("ReadCancelled", ServerLogLevel.Info, Username);
                        break;
                    }
                    catch (InvalidDataException ide)
                    {
                        // Framing error (invalid length etc.) — logs and stops processing this connection.
                        ServerLogger.LogLocalized("InvalidFrameLength", ServerLogLevel.Warn, Username, ide.Message);
                        break;
                    }
                    catch (IOException)
                    {
                        // Underlying stream closed or IO error — breaks to cleanup.
                        ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
                        break;
                    }
                    catch (Exception ex)
                    {
                        // Unexpected error while reading — logs and breaks for cleanup.
                        ServerLogger.LogLocalized("ReadPacketsProtocolError", ServerLogLevel.Warn, ex.Message);
                        break;
                    }

                    if (framedBody == null || framedBody.Length == 0)
                    {
                        ServerLogger.LogLocalized("EmptyFrame", ServerLogLevel.Warn, Username);
                        continue;
                    }

                    // Parses packet body and dispatches by opcode.
                    try
                    {
                        using var ms = new MemoryStream(framedBody);
                        var bodyReader = new PacketReader(ms);

                        byte opcodeByte = await bodyReader.ReadByteAsync(cancellationToken).ConfigureAwait(false);
                        var opcode = (ServerPacketOpCode)opcodeByte;

                        switch (opcode)
                        {
                            case ServerPacketOpCode.RosterBroadcast:
                                await Program.BroadcastRosterAsync(cancellationToken).ConfigureAwait(false);
                                break;

                            case ServerPacketOpCode.PublicKeyRequest:
                                {
                                    var requestSender = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var requestTarget = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    await Program.RelayPublicKeyRequest(requestSender, requestTarget, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.PublicKeyResponse:
                                {
                                    var responseSender = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var publicKeyDer = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    var responseRecipient = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    await Program.RelayPublicKeyToUser(responseSender, publicKeyDer, responseRecipient, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.PlainMessage:
                                {
                                    var senderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var text = await bodyReader.ReadStringAsync(cancellationToken).ConfigureAwait(false);
                                    ServerLogger.LogLocalized("PlainMessageReceived", ServerLogLevel.Info, Username, text);
                                    await Program.BroadcastPlainMessage(text, senderUid, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.EncryptedMessage:
                                {
                                    var encSenderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var encRecipientUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var ciphertext = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    await Program.RelayEncryptedMessageToAUser(ciphertext, encSenderUid, encRecipientUid, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.DisconnectNotify:
                                {
                                    var disconnectedUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    if (Interlocked.CompareExchange(ref _disconnectNotifySent, 1, 0) == 0)
                                    {
                                        await Program.BroadcastDisconnectNotify(disconnectedUid, cancellationToken).ConfigureAwait(false);
                                    }
                                    else
                                    {
                                        ServerLogger.LogLocalized("DisconnectNotifyAlreadySent", ServerLogLevel.Debug, Username, disconnectedUid.ToString());
                                    }
                                    break;
                                }

                            case ServerPacketOpCode.Handshake:
                                ServerLogger.LogLocalized("UnexpectedHandshake", ServerLogLevel.Warn, Username);
                                break;

                            case ServerPacketOpCode.ForceDisconnectClient:
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
                        // Cancellation observed while parsing/dispatching.
                        ServerLogger.LogLocalized("PacketProcessingCancelled", ServerLogLevel.Debug, Username);
                        break;
                    }
                    catch (Exception ex)
                    {
                        // Parsing or dispatch error: logs and closes this connection to avoid protocol corruption.
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
                // Ensures idempotent cleanup runs once.
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
            // Ensures that only the first caller performs the close logic.
            if (Interlocked.Exchange(ref _closed, 1) == 1)
                return;

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
                // Optional notification hooks could be invoked here.
            }
        }
    }
}


