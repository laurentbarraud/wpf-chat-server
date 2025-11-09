/// <file>ServerConnectionHandler.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 9th, 2025</date>

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
        /// • Accepts a connected TcpClient and assigns it to the connection object.
        /// • Wraps the client's network stream with a PacketReader for framed reads.
        /// • Reads the 4‑byte handshake length header from the stream and logs it for diagnosis.
        /// • Converts the header from network byte order to host order and validates it against size limits.
        /// • On invalid length, logs the reason, closes the socket defensively, and throws an exception.
        /// </summary>
        /// <param name="client">Accepted TcpClient instance.</param>
        public ServerConnectionHandler(TcpClient client)
        {
            // Assignw raw TcpClient and provisional UID
            ClientSocket = client ?? throw new ArgumentNullException(nameof(client));
            UID = Guid.NewGuid();

            // Creates PacketReader over the underlying stream for framed reads
            packetReader = new PacketReader(ClientSocket.GetStream());

            // NOTE: PacketReader is async-first; constructor remains synchronous and uses GetAwaiter().GetResult()
            // This is a local blocking choice; the per-connection loop remains async.
            try
            {
                // Blocking read of the 4-byte header using the static overload that accepts a Stream
                byte[] headerBytes = PacketReader.ReadExactAsync(ClientSocket.GetStream(), 4, CancellationToken.None).GetAwaiter().GetResult();
                ServerLogger.Log($"RAW_LEN_SERVER={BitConverter.ToString(headerBytes)}", ServerLogLevel.Debug);
                int payloadLength = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(headerBytes, 0));
                ServerLogger.Log($"INT_BE={payloadLength}", ServerLogLevel.Debug);

                const int MaxHandshakePayload = 65_536; // 64 KB sanity bound for handshake payloads
                if (payloadLength <= 0 || payloadLength > MaxHandshakePayload)
                {
                    ServerLogger.LogLocalized("ErrorInvalidHandshakeLength", ServerLogLevel.Warn, UID.ToString(), payloadLength.ToString());

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

                    throw new InvalidDataException("Handshake length invalid");
                }

                // Blocking read of the payload using the static overload that accepts a Stream
                byte[] payload = PacketReader.ReadExactAsync(ClientSocket.GetStream(), payloadLength, CancellationToken.None).GetAwaiter().GetResult();

                // Parses handshake from in-memory stream
                using var ms = new MemoryStream(payload);
                var handshakeReader = new PacketReader(ms);

                var opcode = (ServerPacketOpCode)handshakeReader.ReadByteAsync().GetAwaiter().GetResult();

                if (opcode != ServerPacketOpCode.Handshake)
                {
                    ServerLogger.LogLocalized("ErrorInvalidOperationException", ServerLogLevel.Warn, Username ?? string.Empty, $"{(byte)opcode}");
                    try { ClientSocket.Close(); } catch { }
                    throw new InvalidDataException("Expected Handshake opcode");
                }

                // Reads username and UID
                Username = handshakeReader.ReadStringAsync().GetAwaiter().GetResult();
                UID = handshakeReader.ReadUidAsync().GetAwaiter().GetResult();

                // Reads 4-byte public-key length from the in-memory handshake buffer
                int publicKeyLength = handshakeReader.ReadInt32NetworkOrderAsync().GetAwaiter().GetResult();

                const int MaxPublicKeyLength = 65_536;
                if (publicKeyLength <= 0 || publicKeyLength > MaxPublicKeyLength)
                {
                    ServerLogger.LogLocalized("ErrorPublicKeyLengthInvalid", ServerLogLevel.Warn, UID.ToString());

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

                    ServerLogger.LogLocalized("ErrorInvalidDataException", ServerLogLevel.Warn, UID.ToString(), publicKeyLength.ToString());
                    throw new InvalidDataException($"PublicKey length invalid in handshake: {publicKeyLength}");
                }

                // Reads public key bytes exactly as declared, from the in-memory handshake buffer
                PublicKeyDer = PacketReader.ReadExactAsync(ms, publicKeyLength).GetAwaiter().GetResult();

                _handshakeProcessed = true;
                ServerLogger.LogLocalized("ClientConnected", ServerLogLevel.Info, Username);
                ServerLogger.LogLocalized("StartingPacketLoop", ServerLogLevel.Debug, Username);

                
                if (ClientSocket?.Connected == true)
                {
                    // Starts the per-connection packet loop exactly once
                    if (Interlocked.CompareExchange(ref _readerStarted, 1, 0) == 0)
                    {
                        Task.Run(() => ProcessReadPacketsAsync());
                    }
                }
            }
            catch (Exception)
            {
                // Ensures partial initialization cleaned up before rethrow
                try 
                { 
                    ClientSocket?.Close();
                } 
                catch 
                { 
                }
                throw;
            }
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

            try
            {
                ClientSocket?.Close();
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorClientCleanup", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            try
            {   // Removess user from roster and notifies remaining clients
                _ = Program.BroadcastDisconnectNotify(UID, CancellationToken.None);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorBroadcastDisconnectNotify", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            try
            {
                // Removes and disposes the per-connection send semaphore to avoid resource leaks.
                // Safe to call even if the semaphore was never created.
                Program.RemoveAndDisposeSendSemaphore(UID);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorClientCleanup", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            ServerLogger.LogLocalized("ClientCleanupComplete", ServerLogLevel.Info, Username ?? UID.ToString());
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
                                    await Program.BroadcastRosterAsync(cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.PublicKeyRequest:
                                {
                                    // Reads requester and target UIDs then forwards the request to the target
                                    var requestSender = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var requestTarget = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    await Program.RelayPublicKeyRequest(requestSender, requestTarget, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.PublicKeyResponse:
                                {
                                    // Reads origin UID, the DER-encoded public key, and the intended recipient UID,
                                    // then relays the public key back to the requester
                                    var responseSender = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var publicKeyDer = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    var responseRecipient = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    await Program.RelayPublicKeyToUser(responseSender, publicKeyDer, responseRecipient, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.PlainMessage:
                                {
                                    // Reads sender UID and message text, logs receipt, then broadcasts to all clients
                                    var senderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var text = await bodyReader.ReadStringAsync(cancellationToken).ConfigureAwait(false);

                                    ServerLogger.LogLocalized("PlainMessageReceived", ServerLogLevel.Info, Username, text);

                                    // Broadcasts plain text message to all connected users (including sender)
                                    await Program.BroadcastPlainMessage(text, senderUid, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.EncryptedMessage:
                                {
                                    // Reads sender UID, recipient UID and ciphertext then forwards the encrypted payload
                                    var encSenderUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var encRecipientUid = await bodyReader.ReadUidAsync(cancellationToken).ConfigureAwait(false);
                                    var ciphertext = await bodyReader.ReadBytesWithLengthAsync(null, cancellationToken).ConfigureAwait(false);
                                    await Program.RelayEncryptedMessageToAUser(ciphertext, encSenderUid, encRecipientUid, cancellationToken).ConfigureAwait(false);
                                    break;
                                }

                            case ServerPacketOpCode.DisconnectNotify:
                                {
                                    // Reads the UID of the disconnected user and broadcasts a disconnect notification once
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


