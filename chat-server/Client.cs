/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 27th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System;
using System.Net.Sockets;

namespace chat_server
{
    /// <summary>
    /// Represents a connected client.
    /// Listens for framed packets, dispatches by opcode,
    /// and handles graceful disconnect.
    /// </summary>
    public class Client
    {
        public string Username { get; private set; }
        public Guid UID { get; private set; }
        public TcpClient ClientSocket { get; private set; } = null!;
        public byte[] PublicKeyDer { get; private set; }

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

        /// <summary>
        /// • Creates and initializes a connected Client from an accepted TcpClient.  
        /// • Wraps the network stream with a PacketReader and reads the framed handshake payload length.  
        /// • Converts the length from network to host order and validates it against sensible bounds.  
        /// • On invalid or out-of-range length performs a clean socket close and logs the reason.  
        /// • Continues parsing and validating the remaining handshake fields only when the length is valid.  
        /// • Marks the handshake as processed only after full validation and starts the per-client reader.
        /// • Throws on fatal initialization errors to prevent partially-initialized clients from being used.
        /// </summary>
        public Client(TcpClient client)
        {
            // Assigns the raw TcpClient and generates a provisional UID for server-side bookkeeping
            ClientSocket = client ?? throw new ArgumentNullException(nameof(client));
            UID = Guid.NewGuid();

            // Creates a PacketReader over the underlying network stream to decode framed payloads
            packetReader = new PacketReader(ClientSocket.GetStream());

            // Reads the 4-byte network-order payload length, converts to host order and validates it.
            int payloadLengthNetworkOrder = packetReader.ReadInt32NetworkOrder();
            int payloadLength = System.Net.IPAddress.NetworkToHostOrder(payloadLengthNetworkOrder);

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
            byte[] payload = packetReader.ReadExact(payloadLength);

            // Parses the handshake fields from the buffered payload
            using var ms = new MemoryStream(payload);
            var handshakeReader = new PacketReader(ms);
            var opcode = (ServerPacketOpCode)handshakeReader.ReadByte();

            // If opcode is not Handshake, logs localized error and aborts initialization
            if (opcode != ServerPacketOpCode.Handshake)
            {
                ServerLogger.LogLocalized("ErrorInvalidOperationException", ServerLogLevel.Warn, Username ?? string.Empty, $"{(byte)opcode}");
                try { ClientSocket.Close(); } catch { }
                throw new InvalidDataException("Expected Handshake opcode");
            }

            // Reads username and UID from the handshake payload
            Username = handshakeReader.ReadString();
            UID = handshakeReader.ReadUid();

            // Reads length-prefixed raw public key bytes (DER) and validates bounds
            int publicKeyLength = handshakeReader.ReadInt32NetworkOrder();

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

                throw new InvalidDataException($"PublicKey length invalid in handshake: {publicKeyLength}");

            }

            // Reads the public key bytes exactly as declared and assigns to the client record
            PublicKeyDer = handshakeReader.ReadExact(publicKeyLength);

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
                    Task.Run(() => ProcessReadPackets());
                }
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
        /// • Reads one framed packet per iteration (4-byte length prefix followed by payload)
        /// • Wraps the payload in a dedicated PacketReader to isolate parsing logic
        /// • Switches on the extracted opcode, invokes the corresponding handler
        /// • Exits the loop on client disconnection or error, then calls CleanupAfterDisconnect
        ///   exactly once.
        /// </summary>
        private void ProcessReadPackets()
        {
            /// <summary>
            /// Defensive startup gate for ProcessReadPackets.
            /// Waits briefly for the server-side handshake flag to be set before consuming framed packets.
            /// Uses a Stopwatch to enforce a precise timeout and a small sleep-based poll to avoid busy-waiting.
            /// If the handshake flag is not observed within the timeout, a warning is logged and the reader exits to prevent stream desynchronization.
            /// </summary>
            {
                // Maximum time to wait for the server-side handshake to be marked processed
                // Chosen small to avoid delaying client processing, but long enough to tolerate scheduling jitter.
                const int handshakeWaitTimeoutMs = 2000;

                // Poll interval between checks of the handshake flag.
                // A small interval keeps latency low without burning CPU in a tight loop.
                const int handshakePollIntervalMs = 20;

                // Stopwatch is used here for elapsed time measurement.
                // Rationale: Stopwatch is not affected by system clock changes and gives accurate elapsed time for timeout checks.
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                // Polls the `_handshakeProcessed` flag until either it becomes true or the timeout elapses.
                while (!_handshakeProcessed && stopwatch.ElapsedMilliseconds < handshakeWaitTimeoutMs)
                {
                    // Each iteration sleeps for handshakePollIntervalMs to yield CPU and reduce contention.
                    System.Threading.Thread.Sleep(handshakePollIntervalMs);
                }

                // If handshake was not completed within the timeout window, logs and aborts the reader.
                // This prevents the reader from misinterpreting handshake bytes as a framed payload length.
                if (!_handshakeProcessed)
                {
                    // Localized warning to help triage which client experienced the timeout.
                    ServerLogger.LogLocalized("HandshakeTimeoutBeforePacketLoop", ServerLogLevel.Warn, Username);

                    // Early return to abort the reader
                    return;
                }

                // Debug trace showing the reader is starting, after the handshake is confirmed.
                ServerLogger.LogLocalized("StartingPacketLoop", ServerLogLevel.Debug, Username);
            }


            try
            {
                // Uses the instance packetReader created during construction.
                // If for any reason it is null, treat as disconnection.
                if (packetReader == null)
                {
                    ServerLogger.LogLocalized("PacketReaderMissing", ServerLogLevel.Warn, Username);
                    return;
                }

                while (true)
                {
                    // If the socket is no longer connected, exits the loop to trigger cleanup.
                    if (ClientSocket == null || ClientSocket?.Connected == false)
                    {
                        ServerLogger.LogLocalized("SocketNotConnected", ServerLogLevel.Info, Username);
                        break;
                    }

                    int bodyLength;
                    try
                    {
                        bodyLength = packetReader.ReadInt32NetworkOrder();
                    }
                    catch (EndOfStreamException)
                    {
                        // Stream closed by remote peer
                        ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
                        break;
                    }

                    if (bodyLength <= 0)
                    {
                        ServerLogger.LogLocalized("InvalidFrameLength", ServerLogLevel.Warn, Username, bodyLength.ToString());
                        break;
                    }

                    byte[] frame = packetReader.ReadExact(bodyLength);
                    using var ms = new MemoryStream(frame);
                    var _packetReader = new PacketReader(ms);

                    var opcode = (ServerPacketOpCode)_packetReader.ReadByte();
                    switch (opcode)
                    {
                        case ServerPacketOpCode.RosterBroadcast:
                            {
                                Program.BroadcastRoster();
                                break;
                            }

                        case ServerPacketOpCode.PublicKeyRequest:
                            {
                                var requestSender = _packetReader.ReadUid();
                                var requestTarget = _packetReader.ReadUid();
                                Program.RelayPublicKeyRequest(requestSender, requestTarget);
                                break;
                            }

                        case ServerPacketOpCode.PublicKeyResponse:
                            {
                                var responseSender = _packetReader.ReadUid();
                                var publicKeyDer = _packetReader.ReadBytesWithLength();
                                var responseRecipient = _packetReader.ReadUid();
                                Program.RelayPublicKeyToUser(responseSender, publicKeyDer, responseRecipient);
                                break;
                            }

                        case ServerPacketOpCode.PlainMessage:
                            {
                                var senderUid = _packetReader.ReadUid();
                                _ = _packetReader.ReadUid(); // discards placeholder
                                var text = _packetReader.ReadString();
                                Program.BroadcastPlainMessage(text, senderUid);
                                break;
                            }

                        case ServerPacketOpCode.EncryptedMessage:
                            {
                                var encSenderUid = _packetReader.ReadUid();
                                var encRecipientUid = _packetReader.ReadUid();
                                var ciphertext = _packetReader.ReadBytesWithLength();
                                Program.RelayEncryptedMessageToAUser(ciphertext, encSenderUid, encRecipientUid);
                                break;
                            }

                        case ServerPacketOpCode.DisconnectNotify:
                            {
                                var disconnectedUid = _packetReader.ReadUid();

                                // Ensures we broadcast this client's disconnect notify at most once.
                                // Use Interlocked to prevent races if Cleanup/other threads attempt broadcast simultaneously.
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

                        default:
                            ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn, Username, $"{(byte)opcode}");
                            break;
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                ServerLogger.LogLocalized("StreamDisposed", ServerLogLevel.Info, Username);
            }
            catch (IOException ioe)
            {
                ServerLogger.LogLocalized("IOError", ServerLogLevel.Info, Username, ioe.Message);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorPacketLoop", ServerLogLevel.Error, Username, ex.ToString());
            }
            finally
            {
                // Ensures cleanup is idempotent and executed exactly once
                CleanupAfterDisconnect();
            }
        }
    }
}


