/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 12th, 2025</date>

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
        public string Username { get; set; }
        public Guid UID { get; set; }
        public TcpClient ClientSocket { get; }
        public string? PublicKeyBase64 { get; set; }
        public byte[]? PublicKeyDer { get; set; }

        private readonly PacketReader _infiniteReader;

        /// <summary>
        /// Constructs a new Client wrapper around the TCP connection.
        /// </summary>
        public Client(TcpClient socket, string username, Guid uid)
        {
            ClientSocket = socket;
            Username = username;
            UID = uid;
            _infiniteReader = new PacketReader(socket.GetStream());
        }

        /// <summary>
        /// Cleans up the TCP connection, removes the client from the roster,
        /// and notifies the remaining clients.
        /// </summary>
        private void CleanupAfterDisconnect()
        {
            try { ClientSocket.Close(); } catch { }
            Program.BroadcastDisconnect(UID.ToString());

            lock (Program.Users)
            {
                if (Program.Users.Remove(this))
                    ServerLogger.LogLocalized("ClientRemoved", ServerLogLevel.Debug, Username, UID.ToString());
            }
        }

        /// <summary>
        /// Continuously reads framed packets, parses them, and delegates actions to Program.
        /// </summary>
        public void ListenForPackets()
        {
            ServerLogger.LogLocalized("StartPacketLoop", ServerLogLevel.Info, Username);

            var stream = ClientSocket.GetStream();
            var reader = new PacketReader(stream);

            while (ClientSocket.Connected)
            {
                try
                {
                    // Reads 4-byte big-endian length prefix
                    byte[] lengthBuffer = reader.ReadExact(4);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(lengthBuffer);

                    int bodyLength = BitConverter.ToInt32(lengthBuffer, 0);
                    if (bodyLength <= 0) continue;

                    // Reads packet body
                    byte[] body = reader.ReadExact(bodyLength);
                    using var ms = new MemoryStream(body);
                    var packetreader = new PacketReader(ms);

                    // Dispatches based on opcode
                    var opcode = (ServerPacketOpCode)packetreader.ReadByte();
  
                    // Uses packets models A to F built in PacketBuilder.cs
                    switch (opcode)
                    {
                        /// <summary>
                        /// Model A: (opcode + UID + username).
                        /// </summary>
                        case ServerPacketOpCode.ConnectionBroadcast:
                            // list of users update : broadcast full list
                            Program.BroadcastConnection();
                            break;

                        /// <summary>
                        /// Model B: (opcode + sender UID + target UID).
                        /// </summary>
                        case ServerPacketOpCode.PublicKeyRequest:
                            {
                                Guid requester = packetreader.ReadUid();
                                Guid target = packetreader.ReadUid();
                                Program.RelayPublicKeyRequest(requester, target);
                                break;
                            }

                        /// <summary>
                        /// Model D: (opcode + sender UID + public key).
                        /// </summary>
                        case ServerPacketOpCode.PublicKeyResponse:
                            {
                                Guid origin = packetreader.ReadUid();
                                string key = packetreader.ReadString();
                                Guid requester = packetreader.ReadUid();
                                Program.RelayPublicKeyToUser(origin, key, requester);
                                break;
                            }

                        /// <summary>
                        /// Model C: (opcode + sender UID + message).
                        /// </summary>
                        case ServerPacketOpCode.PlainMessage:
                            {
                                Guid sender = packetreader.ReadUid();
                                Guid ignore = packetreader.ReadUid();
                                string text = packetreader.ReadString();
                                Program.BroadcastPlainMessage(text, sender);
                                break;
                            }

                        /// <summary>
                        /// Model E: (opcode + sender UID + encrypted payload).
                        /// </summary>
                        case ServerPacketOpCode.EncryptedMessage:
                            {
                                Guid sender = packetreader.ReadUid();
                                Guid recipient = packetreader.ReadUid();
                                byte[] cipher = packetreader.ReadBytesWithLength();
                                string cipherB64 = Convert.ToBase64String(cipher);
                                Program.RelayEncryptedMessageToAUser(cipherB64, sender, recipient);
                                break;
                            }

                        /// <summary>
                        /// Model A: (opcode + UID + username).
                        /// </summary>                    
                        case ServerPacketOpCode.DisconnectNotify:
                            {
                                Guid discUid = packetreader.ReadUid();
                                Program.BroadcastDisconnect(discUid.ToString());
                                break;
                            }

                        /// <summary>
                        /// Model F: (opcode + recipient UID).
                        /// </summary>
                        case ServerPacketOpCode.DisconnectClient:
                            {
                                // Server-initiated shutdown for this client
                                CleanupAfterDisconnect();
                                return;
                            }

                        default:
                            ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn, Username, $"{opcode}");
                            break;
                    }
                }
                catch (EndOfStreamException)
                {
                    ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
                    CleanupAfterDisconnect();
                    return;
                }
                catch (IOException ex)
                {
                    ServerLogger.LogLocalized("IOError", ServerLogLevel.Info, Username, ex.Message);
                    CleanupAfterDisconnect();
                    return;
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("PacketLoopError", ServerLogLevel.Error, Username, ex.Message);
                    CleanupAfterDisconnect();
                    return;
                }
            }
        }
    }
}

