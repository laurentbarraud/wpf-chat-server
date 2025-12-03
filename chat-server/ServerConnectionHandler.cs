/// <file>ServerConnectionHandler.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 4th, 2025</date>

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
        /// Computed property that indicates whether the connection is established on the server side.
        /// Returns true if the TCP socket is connected and handshake has been fully processed.
        /// </summary>
        public bool IsEstablished
        {
            get
            {
                return ClientSocket?.Connected == true && _handshakeProcessed;
            }
        }

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

        // One-time close guard used by TryCloseConnectionSafely
        private int _closed = 0;

        /// <summary>
        /// Per-connection CancellationTokenSource used to cancel the read loop or shutdown this connection.
        /// </summary>
        private CancellationTokenSource? _connectionCts;

        /// <summary>
        /// Guard to ensure a single disconnect-notify is broadcast for this client.
        /// 0 = not sent, 1 = sent.
        /// </summary>
        private int _disconnectNotifySent = 0;

        /// <summary>
        /// True when this client's handshake has been fully processed on the server side.
        /// Placed with other instance fields in Client.cs.
        /// Using volatile ensures reads/writes are immediately visible across threads 
        /// without heavier synchronization.
        /// </summary>
        private volatile bool _handshakeProcessed = false;

        ///<summary>
        /// Atomic flag used to ensure the per-client packet reader is started once.
        /// 0 = not started, 1 = started
        /// </summary>
        private int _readerStarted = 0;

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
        /// <remarks>
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
        /// </remarks>
        private void CleanupAfterDisconnect()
        {
            // Ensures cleanup runs only once
            if (Interlocked.CompareExchange(ref _cleanupState, 1, 0) != 0)
                return;

            // Final localized log for all disconnect scenarios
            ServerLogger.LogLocalized("ClientRemoved", ServerLogLevel.Info, Username ?? UID.ToString());
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
                // Waits briefly for the accept loop to mark the handshake as processed.
                const int handshakeWaitTimeoutMs = 2000;
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                while (!_handshakeProcessed && stopwatch.ElapsedMilliseconds < handshakeWaitTimeoutMs)
                {
                    // Produces to avoid busy-waiting and let cancellation be observed.
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
                                    /// <summary>
                                    /// Handles a public-key request packet.
                                    /// Reads requester and target UIDs, then relays the request to the target client.
                                    /// This path is tolerant: if target not connected/established, logs and returns without fatal error.
                                    /// </summary>
                                    var requestSender = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var requestTarget = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    await Program.RelayPublicKeyRequest(requestSender, requestTarget, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.PublicKeyResponse:
                                {
                                    /// <summary> Reads origin UID, DER key, and requester UID from the packet. </summary>
                                    var originUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var publicKeyDer = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    var requesterUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    /// <summary> Updates the origin user's public key in the in-memory roster (if present). </summary>
                                    var origin = Program.Users.FirstOrDefault(u => u.UID == originUid);
                                    if (origin != null)
                                    {
                                        origin.PublicKeyDer = publicKeyDer ?? Array.Empty<byte>();
                                        ServerLogger.Log($"Registered/updated public key for {originUid}", ServerLogLevel.Info);
                                    }
                                    else
                                    {
                                        ServerLogger.Log($"Origin user {originUid} not found in roster; proceeding to relay.", ServerLogLevel.Warn);
                                    }

                                    /// <summary> Relays the origin's public key to the requester client. </summary>
                                    var requester = Program.Users.FirstOrDefault(u => u.UID == requesterUid);
                                    if (requester?.ClientSocket?.Connected == true && requester.IsEstablished)
                                    {
                                        var builder = new PacketBuilder();
                                        builder.WriteOpCode((byte)ServerPacketOpCode.PublicKeyResponse);
                                        builder.WriteUid(originUid);
                                        builder.WriteBytesWithLength(publicKeyDer ?? Array.Empty<byte>());
                                        builder.WriteUid(requesterUid);

                                        var payload = builder.GetPacketBytes();
                                        await Program.SendFramedAsync(requester, payload, cancellationToken).ConfigureAwait(false);
                                        ServerLogger.LogLocalized("PublicKeyRelaySuccess", ServerLogLevel.Debug, requester.Username);
                                    }
                                    else
                                    {
                                        ServerLogger.LogLocalized("PublicKeyRelayFailed", ServerLogLevel.Warn, requester?.Username ?? requesterUid.ToString(), "Requester not connected/established");
                                    }

                                    break;
                                }


                            case ServerPacketOpCode.PlainMessage:
                                {
                                    Guid senderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    string text = await bodyReader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                    // Safe: resource expects a single argument
                                    ServerLogger.LogLocalized("PlainMessageReceived", ServerLogLevel.Info, Username, text);

                                    await Program.BroadcastPlainMessage(text, senderUid, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.EncryptedMessage:
                                {
                                    Guid senderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    Guid recipientUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    byte[] ciphertext = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);

                                    if (ciphertext == null || ciphertext.Length == 0)
                                    {
                                        ServerLogger.LogLocalized("EncryptedPayloadEmpty", ServerLogLevel.Warn, Username);
                                        break;
                                    }

                                    // Safe: resource expects a single argument
                                    ServerLogger.LogLocalized("EncryptedMessageReceived", ServerLogLevel.Info, Username, ciphertext.Length.ToString());

                                    await Program.RelayEncryptedMessageToAUser(ciphertext, senderUid, recipientUid, cancellationToken).ConfigureAwait(false);
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
                                /// <summary>
                                /// Unknown opcode is tolerated; logs warning and continues without killing the session.
                                /// This ensures dynamic public-key updates or future opcodes do not crash the pipeline.
                                /// </summary>
                                ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn, Username, $"{(byte)opcode}");
                                // Do not close connection; simply continue loop
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


