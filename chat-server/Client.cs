/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 23th, 2025</date>

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
        public TcpClient ClientSocket { get; set; }
        public byte[] PublicKeyDer { get; private set; }

        private readonly PacketReader packetReader;

        private volatile bool _cleanupDone = false;

        /// <summary>
        /// • Initializes a new connected client, parses the framed handshake payload.
        /// • Validates received fields: username, UID, public key DER.
        /// • Logs errors and closes the socket on invalid input.
        /// • Starts the per-client packet reading loop only when the socket remains connected.
        /// </summary>
        public Client(TcpClient client)
        {
            // Assigns the raw TcpClient and generates a provisional UID for server-side bookkeeping
            ClientSocket = client;
            UID = Guid.NewGuid();

            // Creates a PacketReader over the underlying network stream to decode framed payloads
            packetReader = new PacketReader(ClientSocket.GetStream());

            // Reads the 4-byte network-order payload length and validates it
            int payloadLength = packetReader.ReadInt32NetworkOrder();
            if (payloadLength <= 0)
            {
                ServerLogger.LogLocalized("ErrorInvalidHandshakeLength", ServerLogLevel.Warn, UID.ToString());
                try { ClientSocket.Close(); } catch { }
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

            // Logs successful connection and starts the per-client packet read loop only if still connected
            ServerLogger.LogLocalized("ClientConnected", ServerLogLevel.Info, Username);

            if (ClientSocket?.Connected == true)
            {
                Task.Run(() => ProcessReadPackets());
            }
        }

        /// <summary>
        /// Performs a safe cleanup of the client connection and notifies the server.
        /// Ensures resources are closed and the disconnect is broadcasted exactly once.
        /// </summary>
        private void CleanupAfterDisconnect()
        {
            try
            {
                ClientSocket?.Close();
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorClientCleanup", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            // Removes user from roster and notifies remaining clients
            try
            {
                Program.BroadcastDisconnectNotify(UID);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("ErrorClientCleanup", ServerLogLevel.Warn, Username ?? UID.ToString(), ex.Message);
            }

            ServerLogger.LogLocalized("ClientCleanupComplete", ServerLogLevel.Info, Username ?? UID.ToString());
        }

        /// <summary>
        /// • Reads one framed packet per iteration (4-byte length prefix followed by payload).  
        /// • Wraps the payload in a dedicated PacketReader to isolate parsing logic.  
        /// • Switches on the extracted opcode and invokes the corresponding handler.  
        /// • Exits the loop on client disconnection or error, then calls CleanupAfterDisconnect() exactly once.  
        /// </summary>
        private void ProcessReadPackets()
        {
            ServerLogger.LogLocalized("StartPacketLoop", ServerLogLevel.Info, Username);

            try
            {
                while (true)
                {
                    int bodyLength = packetReader.ReadInt32NetworkOrder();
                    if (bodyLength <= 0)
                    {
                        ServerLogger.LogLocalized("InvalidFrameLength", ServerLogLevel.Warn, Username, bodyLength.ToString());
                        break; // break to reach finally and cleanup
                    }

                    byte[] frame = packetReader.ReadExact(bodyLength);
                    using var ms = new MemoryStream(frame);
                    var _packetReader = new PacketReader(ms);

                    var opcode = (ServerPacketOpCode)_packetReader.ReadByte();
                    switch (opcode)
                    {
                        case ServerPacketOpCode.RosterBroadcast:
                            Program.BroadcastRoster();
                            break;

                        case ServerPacketOpCode.PublicKeyRequest:
                            var requestSender = _packetReader.ReadUid();
                            var requestTarget = _packetReader.ReadUid();
                            Program.RelayPublicKeyRequest(requestSender, requestTarget);
                            break;

                        case ServerPacketOpCode.PublicKeyResponse:
                            var responseSender = _packetReader.ReadUid();
                            var publicKeyDer = _packetReader.ReadBytesWithLength();
                            var responseRecipient = _packetReader.ReadUid();
                            Program.RelayPublicKeyToUser(responseSender, publicKeyDer, responseRecipient);
                            break;

                        case ServerPacketOpCode.PlainMessage:
                            var senderUid = _packetReader.ReadUid();
                            _ = _packetReader.ReadUid(); // discards placeholder
                            var text = _packetReader.ReadString();
                            Program.BroadcastPlainMessage(text, senderUid);
                            break;

                        case ServerPacketOpCode.EncryptedMessage:
                            var encSenderUid = _packetReader.ReadUid();
                            var encRecipientUid = _packetReader.ReadUid();
                            var ciphertext = _packetReader.ReadBytesWithLength();

                            // Relays raw binary ciphertext
                            Program.RelayEncryptedMessageToAUser(ciphertext, encSenderUid, encRecipientUid);
                            break;


                        case ServerPacketOpCode.DisconnectNotify:
                            var disconnectedUid = _packetReader.ReadUid();
                            Program.BroadcastDisconnectNotify(disconnectedUid);
                            break;

                        default:
                            ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn, Username, $"{(byte)opcode}");
                            break;
                    }
                }
            }
            catch (EndOfStreamException)
            {
                ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
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
                ServerLogger.LogLocalized("PacketLoopError", ServerLogLevel.Error, Username, ex.ToString());
            }
            finally
            {
                // Ensure cleanup is idempotent and logs reason
                CleanupAfterDisconnect();
            }
        }
    }
}


