/// <file>ServerConnectionHandler.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 31th, 2025</date>
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
        public string Username { get; private set; } = string.Empty;
        public Guid UID { get; private set; }
        public TcpClient ClientSocket { get; private set; } = null!;
        public byte[] PublicKeyDer { get; private set; } = Array.Empty<byte>();

        private readonly PacketReader packetReader;

        private int _cleanupState = 0; // field in Client class: 0 = not cleaned, 1 = cleaning/done

        /// <summary>
        /// Guard to ensure we broadcast a given client's disconnect notify at most once.
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
        /// • Creates and initializes a connected Client from an accepted TcpClient.  
        /// • Wraps the network stream with a PacketReader and reads the framed handshake payload length.  
        /// • Converts the length from network to host order and validates it against sensible bounds.  
        /// • On invalid or out-of-range length performs a clean socket close and logs the reason.  
        /// • Continues parsing and validating the remaining handshake fields only when the length is valid.  
        /// • Marks the handshake as processed only after full validation and starts the per-client reader.
        /// • Throws on fatal initialization errors to prevent partially-initialized clients from being used.
        /// </summary>
        public ServerConnectionHandler(TcpClient client)
        {
            // Assigns the raw TcpClient and generates a provisional UID for server-side bookkeeping
            ClientSocket = client ?? throw new ArgumentNullException(nameof(client));
            UID = Guid.NewGuid();

            // Creates a PacketReader over the underlying network stream to decode framed payloads
            packetReader = new PacketReader(ClientSocket.GetStream());

            // NOTE: PacketReader is async-first. The constructor must remain synchronous, so it uses
            // the async APIs with GetAwaiter().GetResult() to preserve the existing control flow.
            // This is an explicit, local blocking choice; the rest of the per-connection loop is async.
            try
            {
                // Reads the 4-byte network-order payload length, converts to host order and validates it.
                int payloadLengthNetworkOrder = packetReader.ReadInt32NetworkOrderAsync().GetAwaiter().GetResult();
                int payloadLength = IPAddress.NetworkToHostOrder(payloadLengthNetworkOrder);

                const int MaxHandshakePayload = 65_536; // 64 KB sanity bound for handshake payloads
                if (payloadLength <= 0 || payloadLength > MaxHandshakePayload)
                {
                    // Logs the invalid length at Warn level for operations visibility
                    ServerLogger.LogLocalized("ErrorInvalidHandshakeLength", ServerLogLevel.Warn, UID.ToString(), payloadLength.ToString());

                    // Ensures the raw socket is closed to free resources and avoid half-open connections
                    try
                    {
                        if (ClientSocket == null || !ClientSocket.Connected)
                        {
                            ServerLogger.LogLocalized("SocketAlreadyClosed", ServerLogLevel.Debug, UID.ToString());
                        }
                        ClientSocket?.Close();
                    }
                    catch
                    {
                        ServerLogger.LogLocalized("SocketCloseFailed", ServerLogLevel.Debug, UID.ToString());
                    }

                    // Throws after cleanup to preserve existing control flow (caller expects an exception).
                    throw new InvalidDataException("Handshake length invalid");
                }

                // Reads exactly payloadLength bytes from the stream into a temporary buffer
                byte[] payload = PacketReader.ReadExactAsync(ClientSocket.GetStream(), payloadLength).GetAwaiter().GetResult();

                // Parses the handshake fields from the buffered payload
                using var ms = new MemoryStream(payload);
                var handshakeReader = new PacketReader(ms);
                var opcode = (ServerPacketOpCode)handshakeReader.ReadByteAsync().GetAwaiter().GetResult();

                // If opcode is not Handshake, logs localized error and aborts initialization
                if (opcode != ServerPacketOpCode.Handshake)
                {
                    ServerLogger.LogLocalized("ErrorInvalidOperationException", ServerLogLevel.Warn, Username ?? string.Empty, $"{(byte)opcode}");
                    try { ClientSocket.Close(); } catch { }
                    throw new InvalidDataException("Expected Handshake opcode");
                }

                // Reads username and UID from the handshake payload
                Username = handshakeReader.ReadStringAsync().GetAwaiter().GetResult();
                UID = handshakeReader.ReadUidAsync().GetAwaiter().GetResult();

                // Reads length-prefixed raw public key bytes (DER) and validates bounds
                int publicKeyLengthNetwork = handshakeReader.ReadInt32NetworkOrderAsync().GetAwaiter().GetResult();
                int publicKeyLength = IPAddress.NetworkToHostOrder(publicKeyLengthNetwork);

                // Protects against invalid or malicious length fields
                const int MaxPublicKeyLength = 65_536;
                if (publicKeyLength <= 0 || publicKeyLength > MaxPublicKeyLength)
                {
                    // Logs and defensive closes when public key length is invalid
                    ServerLogger.LogLocalized("ErrorPublicKeyLengthInvalid", ServerLogLevel.Warn, UID.ToString());

                    try
                    {
                        // If the socket is already closed or disposed, logs at Debug level for diagnostics
                        if (ClientSocket == null || !ClientSocket.Connected)
                        {
                            ServerLogger.LogLocalized("SocketAlreadyClosed", ServerLogLevel.Debug, UID.ToString());
                        }

                        ClientSocket?.Close();
                    }
                    catch
                    {
                        // Best-effort close; avoid throwing during error handling
                        ServerLogger.LogLocalized("SocketCloseFailed", ServerLogLevel.Debug, UID.ToString());
                    }

                    ServerLogger.LogLocalized("ErrorInvalidDataException", ServerLogLevel.Warn, UID.ToString(), publicKeyLength.ToString());
                    throw new InvalidDataException($"PublicKey length invalid in handshake: {publicKeyLength}");
                }

                // Reads the public key bytes exactly as declared and assigns to the client record
                PublicKeyDer = handshakeReader.ReadExactAsync(publicKeyLength).GetAwaiter().GetResult();

                // Mark the handshake as processed so server-side code knows the framed stream is aligned
                _handshakeProcessed = true;

                // Logs successful connection (preserve existing behavior)
                ServerLogger.LogLocalized("ClientConnected", ServerLogLevel.Info, Username);

                // Debug log to trace exactly when the per-client packet loop is started
                ServerLogger.LogLocalized("StartingPacketLoop", ServerLogLevel.Debug, Username);

                /// <summary>
                /// Starts the packet reader task once if the socket is connected.
                /// Uses Interlocked.CompareExchange to atomically set _readerStarted from 0 to 1.
                /// If the call returns 0, this thread won the race and is allowed to start the Task.
                /// If it returns a non-zero value, another thread already started the reader and we skip starting it again.
                /// </summary>
                if (ClientSocket?.Connected == true)
                {
                    /// <summary> 
                    /// Tries to atomically change _readerStarted from 0 to 1
                    /// </summary> 
                    if (Interlocked.CompareExchange(ref _readerStarted, 1, 0) == 0)
                    {
                        // Start the async packet loop that uses the async PacketReader APIs
                        Task.Run(() => ProcessReadPacketsAsync());
                    }
                }
            }
            catch (Exception)
            {
                // Ensures any partially opened socket is closed before rethrowing to preserve existing behavior
                try { ClientSocket?.Close(); } catch { }
                throw;
            }
        }

        /// <summary>
        /// Performs an atomic compare-and-swap on the cleanup flag :
        /// if the current value equals 0, set it to 1 and return success; otherwise indicate another thread won.
        /// This operation is fast, thread-safe and provided by System.Threading. 
        /// It prevents concurrent threads from executing the cleanup sequence more than once, avoiding duplicated
        /// socket closes, duplicate broadcast notifications, and reentrancy-related exceptions.
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
            ///   The test!= 0 in the code therefore means: «if the previous value was not 0, we do nothing and we exit».
            /// </summary>
            if (Interlocked.CompareExchange(ref _cleanupState, 1, 0) != 0)
                return;

            try
            {
                ClientSocket?.Close();
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorClientCleanup", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            try
            {   /// <summary>Removes user from roster and notifies remaining clients</summary>
                Program.BroadcastDisconnectNotify(UID);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorClientCleanup", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            ServerLogger.LogLocalized("ClientCleanupComplete", ServerLogLevel.Info, Username ?? UID.ToString());
        }

        /// <summary>
        /// Sends a framed handshake acknowledgement to the connected client.
        /// Uses an explicit HandshakeAck opcode (ServerPacketOpCode.HandshakeAck) as a single-byte payload.
        /// The write is awaited to guarantee ordering and flushed to the socket.
        /// </summary>
        private async Task SendHandshakeAckAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Uses explicit HandshakeAck opcode; ensures Protocol enum contains HandshakeAck = 2
                byte[] payload = new byte[] 
                { 
                    (byte)ServerPacketOpCode.HandshakeAck 
                };

                int netOrder = IPAddress.HostToNetworkOrder(payload.Length);
                byte[] header = BitConverter.GetBytes(netOrder);

                // Combines header + payload in a single buffer to issue a single write
                var framed = new byte[4 + payload.Length];
                Buffer.BlockCopy(header, 0, framed, 0, 4);
                Buffer.BlockCopy(payload, 0, framed, 4, payload.Length);

                var stream = ClientSocket.GetStream();
                await stream.WriteAsync(framed, 0, framed.Length, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Writes failure should trigger safe close to avoid half-open connections.
                ServerLogger.LogLocalized("HandshakeAckSendFailed", ServerLogLevel.Warn, Username, ex.Message);
                TryCloseConnectionSafely(ex);
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

        /// <summary>
        /// Performs the per-connection read loop asynchronously.
        /// Reads framed bodies using PacketReader.ReadFramedBodyAsync and dispatches packets by opcode.
        /// Ensures robust framing, length validation, and centralized error handling.
        /// </summary>
        private async Task ProcessReadPacketsAsync()
        {
            // Uses a per-connection cancellation token source if available; otherwise use CancellationToken.None.
            CancellationToken cancellationToken = CancellationToken.None;

            try
            {
                // Waits briefly for handshake to be marked processed by the constructor logic.
                const int handshakeWaitTimeoutMs = 2000;
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                while (!_handshakeProcessed && stopwatch.ElapsedMilliseconds < handshakeWaitTimeoutMs)
                {
                    // Yields control to avoid busy-waiting while remaining responsive to cancellation.
                    await Task.Yield();
                }

                if (!_handshakeProcessed)
                {
                    // If handshake was not processed in time, closew cleanly to avoid protocol desync.
                    ServerLogger.LogLocalized("HandshakeTimeoutBeforePacketLoop", ServerLogLevel.Warn, Username);
                    TryCloseConnectionSafely(null);
                    return;
                }

                ServerLogger.LogLocalized("StartingPacketLoop", ServerLogLevel.Debug, Username);

                var stream = ClientSocket.GetStream();

                // Main loop: reads framed packets until socket closes or a fatal error occurs.
                while (true)
                {
                    if (ClientSocket == null || !ClientSocket.Connected)
                    {
                        ServerLogger.LogLocalized("SocketNotConnected", ServerLogLevel.Info, Username);
                        break;
                    }

                    byte[] framedBody;
                    try
                    {
                        // Reads the framed body (4-byte BE length + payload) as a single atomic async operation.
                        framedBody = await packetReader.ReadFramedBodyAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (InvalidDataException ide)
                    {
                        // Frame length invalid — breaks and cleanup.
                        ServerLogger.LogLocalized("InvalidFrameLength", ServerLogLevel.Warn, Username, ide.Message);
                        break;
                    }
                    catch (IOException)
                    {
                        // Remote closed or IO error — breaks to cleanup.
                        ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        ServerLogger.LogLocalized("ReadCancelled", ServerLogLevel.Info, Username);
                        break;
                    }

                    if (framedBody == null || framedBody.Length == 0)
                    {
                        ServerLogger.LogLocalized("EmptyFrame", ServerLogLevel.Warn, Username);
                        continue;
                    }

                    // Parses the packet body and dispatches based on opcode.
                    try
                    {
                        using var ms = new MemoryStream(framedBody);
                        var bodyReader = new PacketReader(ms);

                        // Reads opcode (single byte)
                        var opcodeByte = (await bodyReader.ReadByteAsync(cancellationToken).ConfigureAwait(false));
                        var opcode = (ServerPacketOpCode)opcodeByte;

                        switch (opcode)
                        {
                            case ServerPacketOpCode.RosterBroadcast:
                                {
                                    Program.BroadcastRoster();
                                    break;
                                }

                            case ServerPacketOpCode.PublicKeyRequest:
                                {
                                    var requestSender = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var requestTarget = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    Program.RelayPublicKeyRequest(requestSender, requestTarget);
                                    break;
                                }

                            case ServerPacketOpCode.PublicKeyResponse:
                                {
                                    var responseSender = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var publicKeyDer = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    var responseRecipient = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    Program.RelayPublicKeyToUser(responseSender, publicKeyDer, responseRecipient);
                                    break;
                                }

                            case ServerPacketOpCode.PlainMessage:
                                {
                                    var senderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var text = await bodyReader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                    ServerLogger.LogLocalized("PlainMessageReceived", ServerLogLevel.Info, Username, text);

                                    // Broadcasts plain message to all users (including sender)
                                    Program.BroadcastPlainMessage(text, senderUid);
                                    break;
                                }

                            case ServerPacketOpCode.EncryptedMessage:
                                {
                                    var encSenderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var encRecipientUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var ciphertext = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    Program.RelayEncryptedMessageToAUser(ciphertext, encSenderUid, encRecipientUid);
                                    break;
                                }

                            case ServerPacketOpCode.DisconnectNotify:
                                {
                                    var disconnectedUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    if (Interlocked.CompareExchange(ref _disconnectNotifySent, 1, 0) == 0)
                                    {
                                        Program.BroadcastDisconnectNotify(disconnectedUid);
                                    }
                                    else
                                    {
                                        ServerLogger.LogLocalized("DisconnectNotifyAlreadySent", ServerLogLevel.Debug, Username, disconnectedUid.ToString());
                                    }
                                    break;
                                }

                            case ServerPacketOpCode.Handshake:
                                {
                                    ServerLogger.LogLocalized("UnexpectedHandshake", ServerLogLevel.Warn, Username);
                                    break;
                                }

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
                                {
                                    ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn, Username, $"{(byte)opcode}");
                                    break;
                                }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Parsing/dispatch error: logs and performs a safe connection close.
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
                // Ensures idempotent cleanup is executed exactly once.
                CleanupAfterDisconnect();
            }
        }
    }
}


