/// <file>ServerConnectionHandler.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 15th, 2026</date>

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
        /// <summary>
        /// The logged-in username for this connection.
        /// </summary>
        public string Username { get; private set; } = string.Empty;

        /// <summary>
        /// The unique identifier for this connection/client.
        /// </summary>
        public Guid UID { get; private set; } = Guid.Empty;

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

            // Creates a PacketReader over the underlying network stream for framed reads.
            // PacketReader is async-first.
            packetReader = new PacketReader(ClientSocket.GetStream());
        }

        /// <summary>
        /// Performs final cleanup sequence for this client,
        /// ensuring it runs exactly once even if multiple threads detect the disconnection.
        /// This method atomically marks the connection as closed, removes the user from the roster
        /// and broadcasts DisconnectNotify.
        /// </summary>
        /// <remarks>
        /// Interlocked.CompareExchange is used to guarantee that only the first caller
        /// performs the cleanup logic:
        /// • ref _cleanupState — the cleanup flag passed by reference.
        /// • 1 — the value to assign if the current value matches the expected one.
        /// • 0 — the expected value; cleanup proceeds only if the flag was still 0.
        /// The return value is the previous state. 
        /// If it was not 0, another thread has already executed cleanup, and the method exits immediately.
        /// This prevents duplicate socket closes, duplicate user removals, etc.
        /// </remarks>
        private void CleanupAfterDisconnect()
        {
            if (Interlocked.CompareExchange(ref _cleanupState, 1, 0) != 0)
            {
                return;
            }

            try
            {
                ServerConnectionHandler? myConnectionHandler;

                // Removes myConnectionHandler exactly once
                lock (Program.Users)
                {
                    // LINQ FirstOrDefault request:
                    // Iterates over Program.Users and return the first element
                    // where the lambda (c => c.UID == UID) is true. 
                    // If no match exists, returns null.
                    // In plain English:
                    //   "Look through Program.Users and give me the user whose UID equals my UID."
                    myConnectionHandler = Program.Users.FirstOrDefault(u => u.UID == UID);

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
        /// Finalizes a connection after an async handshake has been validated by the accept loop.
        /// • Sets handshake-derived properties (Username, UID, PublicKeyDer) and marks the handler ready.
        /// • Creates a per-connection CancellationTokenSource linked to the provided serverToken so the
        ///   read loop can be cancelled when the server shuts down or when the connection is closed.
        /// • Starts the per-connection read loop exactly once on the thread-pool, passing the linked token
        ///   so reads and dispatching observe cooperative cancellation.
        /// • Ensures any previous connection CTS is disposed to avoid resource leaks.
        /// </summary>

        internal void InitializeAfterHandshake(string username, Guid uid, byte[] publicKey, CancellationToken serverToken = default)
        {
            // Populates handshake-derived state
            this.Username = username ?? string.Empty;
            this.UID = uid;
            PublicKeyDer = publicKey ?? Array.Empty<byte>();
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
                        var opcode = (PacketOpCode)opcodeByte;

                        switch (opcode)
                        {
                            case PacketOpCode.RosterBroadcast:
                                await Program.BroadcastRosterAsync(cancellationToken).ConfigureAwait(false);
                                break;

                            case PacketOpCode.PublicKeyRequest:
                                {
                                    // Handles a public-key request packet.
                                    // Reads requester and target UIDs, then relays the request to the target client.
                                    // This path is tolerant: if target not connected/established, logs and returns without fatal error.
                                    var requestSender = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var requestTarget = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    await Program.RelayPublicKeyRequest(requestSender, requestTarget, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case PacketOpCode.PublicKeyResponse:
                                {
                                    // Reads origin UID, DER key, and requester UID from the packet.
                                    // • originUserKeyUid: owner of the public key being registered/updated
                                    // • publicKey: DER-encoded RSA public key (may be empty for "clear mode")
                                    // • publicKeyRequesterUid: target user who requested this key
                                    var requesterUserPublicKeyUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var publicKey = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    var publicKeyRequesterUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);

                                    // Updates the origin user's public key in the in-memory roster (if present).
                                    // This keeps the server-side snapshot consistent for subsequent broadcasts.
                                    var requesterUser = Program.Users.FirstOrDefault(u => u.UID == requesterUserPublicKeyUid);
                                    
                                    if (requesterUser != null)
                                    {
                                        requesterUser.PublicKeyDer = publicKey ?? Array.Empty<byte>();
                                        ServerLogger.Log($"Registered/updated public key for {requesterUser?.Username ?? "<unknown>"}", ServerLogLevel.Info);
                                    }
                                    else
                                    {
                                        ServerLogger.Log($"Origin user {requesterUserPublicKeyUid} not found in roster; proceeding to relay.", ServerLogLevel.Warn);
                                    }

                                    // Relays origin's public key to the requester using the centralized helper.
                                    await Program.RelayPublicKeyToUser(requesterUserPublicKeyUid, publicKey ?? Array.Empty<byte>(),
                                        publicKeyRequesterUid, cancellationToken).ConfigureAwait(false);

                                    // Broadcasts the newly registered/updated key to all other peers.
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
                                    // Reads sender UID, recipient UID, and ciphertext.
                                    Guid senderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    Guid recipientUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    byte[] ciphertext = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);

                                    // Validates ciphertext presence.
                                    if (ciphertext == null || ciphertext.Length == 0)
                                    {
                                        ServerLogger.LogLocalized("EncryptedPayloadEmpty", ServerLogLevel.Warn, Username);
                                        break;
                                    }

                                    // Resolves sender/recipient names from Program.Users, fallbacks to UID then "Unknown user"
                                    string senderDisplayName = Program.Users.FirstOrDefault(u => u.UID == senderUid)?.Username ?? senderUid.ToString() ?? "Unknown user";
                                    string recipientDisplayName = Program.Users.FirstOrDefault(u => u.UID == recipientUid)?.Username ?? recipientUid.ToString() ?? "Unknown user";

                                    ServerLogger.LogLocalized("EncryptedMessageReceived", ServerLogLevel.Info, senderDisplayName, recipientDisplayName);

                                    // Relays only to the intended recipient
                                    await Program.RelayEncryptedMessageToAUser(ciphertext, senderUid, recipientUid, cancellationToken)
                                        .ConfigureAwait(false);

                                    break;
                                }

                            case PacketOpCode.DisconnectNotify:
                                {
                                    var disconnectedUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
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


