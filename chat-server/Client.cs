/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 14th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace chat_server
{
    /// <summary>
    /// Represents a connected client.  
    /// Performs a framed handshake on construction, then listens for framed packets  
    /// and dispatches them by opcode (models A–F). Cleans up on disconnect.  
    /// </summary>
    public class Client
    {
        public string Username { get; private set; }
        public Guid UID { get; private set; }
        public TcpClient ClientSocket { get; }
        public string PublicKeyBase64 { get; private set; }
        public byte[] PublicKeyDer { get; private set; }

        private readonly PacketReader _reader;

        /// <summary>
        /// Constructs a new Client wrapper around the TCP connection.  
        /// Reads and validates the framed handshake packet, registers user,  
        /// broadcasts the roster, and starts the packet‐processing loop.  
        /// </summary>
        /// <param name="socket">Accepted TCP client.</param>
        public Client(TcpClient socket)
        {
            ClientSocket = socket ?? throw new ArgumentNullException(nameof(socket));
            _reader = new PacketReader(socket.GetStream());

            // --- Handshake (framed) ---
            // Reads 4-byte length prefix, then payload
            int length = _reader.ReadInt32NetworkOrder();
            byte[] raw = _reader.ReadExact(length);

            // Parses handshake model: opcode + username + UID + publicKey
            using var ms = new MemoryStream(raw);
            var hsReader = new PacketReader(ms);
            var op = (ServerPacketOpCode)hsReader.ReadOpCode();
            if (op != ServerPacketOpCode.Handshake)
            {
                ServerLogger.LogLocalized("UnexpectedOpcode", ServerLogLevel.Error, "Expected Handshake");
                throw new InvalidOperationException("Invalid handshake");
            }

            Username = hsReader.ReadString();
            UID = hsReader.ReadUid();
            PublicKeyBase64 = hsReader.ReadString();
            PublicKeyDer = Convert.FromBase64String(PublicKeyBase64);

            ServerLogger.LogLocalized("ClientConnected", ServerLogLevel.Info, Username, UID.ToString());

            // Registers in global roster and broadcasts new connection
            lock (Program.Users)
                Program.Users.Add(this);
            Program.BroadcastConnection();

            // Starts listening for further packets
            Task.Run(ProcessPackets);
        }

        /// <summary>
        /// Closes the connection, removes from roster, and notifies others of disconnect.
        /// </summary>
        private void Cleanup()
        {
            try { ClientSocket.Close(); } catch { }
            lock (Program.Users)
            {
                if (Program.Users.Remove(this))
                    ServerLogger.LogLocalized("ClientRemoved", ServerLogLevel.Debug, Username, UID.ToString());
            }
            Program.BroadcastDisconnect(UID.ToString());
        }

        /// <summary>
        /// Continuously reads framed packets, dispatches by opcode,  
        /// and invokes Program methods for each model.  
        /// </summary>
        private void ProcessPackets()
        {
            try
            {
                while (ClientSocket.Connected)
                {
                    // Reads length prefix + body
                    int bodyLen = _reader.ReadInt32NetworkOrder();
                    if (bodyLen <= 0)
                        continue;

                    byte[] body = _reader.ReadExact(bodyLen);
                    using var ms = new MemoryStream(body);
                    var pr = new PacketReader(ms);

                    // Dispatches on opcode
                    var opcode = (ServerPacketOpCode)pr.ReadOpCode();
                    switch (opcode)
                    {
                        // Model C: Plain‐text message
                        case ServerPacketOpCode.PlainMessage:
                            {
                                Guid sender = pr.ReadUid();
                                Guid recipient = pr.ReadUid();
                                string text = pr.ReadString();
                                Program.BroadcastPlainMessage(text, sender);
                                break;
                            }

                        // Model E: Encrypted message
                        case ServerPacketOpCode.EncryptedMessage:
                            {
                                Guid encSender = pr.ReadUid();
                                Guid encRecipient = pr.ReadUid();
                                byte[] cipherPayload = pr.ReadBytesWithLength();
                                string cipherB64 = Convert.ToBase64String(cipherPayload);
                                Program.RelayEncryptedMessageToAUser(cipherB64, encSender, encRecipient);
                                break;
                            }

                        // Model B: Public‐key request
                        case ServerPacketOpCode.PublicKeyRequest:
                            {
                                Guid requester = pr.ReadUid();
                                Guid target = pr.ReadUid();
                                Program.RelayPublicKeyRequest(requester, target);
                                break;
                            }

                        // Model D: Public‐key response
                        case ServerPacketOpCode.PublicKeyResponse:
                            {
                                Guid origin = pr.ReadUid();
                                string keyB64 = pr.ReadString();
                                Guid requester = pr.ReadUid();
                                Program.RelayPublicKeyToUser(origin, keyB64, requester);
                                break;
                            }

                        // Model A: Roster update (server-side triggers a rebroadcast)
                        case ServerPacketOpCode.ConnectionBroadcast:
                            {
                                Program.BroadcastConnection();
                                break;
                            }

                        // Model A : Peer disconnected notification
                        case ServerPacketOpCode.DisconnectNotify:
                            {
                                Guid discUid = pr.ReadUid();
                                Program.BroadcastDisconnect(discUid.ToString());
                                break;
                            }

                        // Model F: Server-initiated client disconnect
                        case ServerPacketOpCode.DisconnectClient:
                            {
                                Cleanup();
                                return;
                            }

                        default:
                            {
                                ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn,
                                Username, $"{opcode}");
                                break;
                            }
                    }
                }
            }
            catch (EndOfStreamException)
            {
                ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
            }
            catch (Exception ex)
            {
                ServerLogger.LogLocalized("PacketLoopError", ServerLogLevel.Error, Username);
            }
            finally
            {
                Cleanup();
            }
        }
    }
}

