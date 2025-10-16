/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 16th, 2025</date>

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
        public string PublicKeyBase64 { get; private set; }
        public byte[] PublicKeyDer { get; private set; }

        private readonly PacketReader packetReader;

        public Client(TcpClient client)
        {
            ClientSocket = client;
            UID = Guid.NewGuid();
            packetReader = new PacketReader(ClientSocket.GetStream());

            // Decodes framed handshake
            int payloadLength = packetReader.ReadInt32NetworkOrder();
            if (payloadLength <= 0)
                throw new InvalidDataException("Handshake length invalid");

            // Reads exactly payloadLength bytes into a temp buffer
            byte[] payload = packetReader.ReadExact(payloadLength);

            // Parses the handshake fields from that buffer
            using var ms = new MemoryStream(payload);
            var handshakeReader = new PacketReader(ms);
            var opcode = (ServerPacketOpCode)handshakeReader.ReadByte();
            if (opcode != ServerPacketOpCode.Handshake)
                throw new InvalidOperationException("Expected Handshake opcode");

            Username = handshakeReader.ReadString();
            UID = handshakeReader.ReadUid();
            PublicKeyBase64 = handshakeReader.ReadString();
            PublicKeyDer = Convert.FromBase64String(PublicKeyBase64);

            ServerLogger.LogLocalized("ClientConnected", ServerLogLevel.Info, Username);

            Task.Run(() => ProcessReadPackets());
        }

        private void CleanupAfterDisconnect()
        {
            try { ClientSocket.Close(); } catch { }
            Program.BroadcastDisconnect(UID.ToString());
        }

        private void ProcessReadPackets()
        {
            ServerLogger.LogLocalized("StartPacketLoop", ServerLogLevel.Info, Username);

            while (true)
            {
                try
                {
                    // Reads next framed packet
                    int bodyLength = packetReader.ReadInt32NetworkOrder();
                    if (bodyLength <= 0)
                        continue;

                    // Reads opcode
                    var opcode = (ServerPacketOpCode)packetReader.ReadByte();

                    switch (opcode)
                    {
                        case ServerPacketOpCode.RosterBroadcast:
                            // (opcode + uid + username + pubKey)
                            Guid newUid = packetReader.ReadUid();
                            string newName = packetReader.ReadString();
                            string newKeyB64 = packetReader.ReadString();
                            Program.BroadcastRoster();
                            break;

                        case ServerPacketOpCode.PublicKeyRequest:
                            Guid reqSender = packetReader.ReadUid();
                            Guid reqTarget = packetReader.ReadUid();
                            Program.RelayPublicKeyRequest(reqSender, reqTarget);
                            break;

                        case ServerPacketOpCode.PublicKeyResponse:
                            Guid respSender = packetReader.ReadUid();
                            string keyB64 = packetReader.ReadString();
                            Guid destUid = packetReader.ReadUid();
                            Program.RelayPublicKeyToUser(respSender, keyB64, destUid);
                            break;

                        case ServerPacketOpCode.PlainMessage:
                            Guid senderUid = packetReader.ReadUid();
                            _ = packetReader.ReadUid(); // discard recipient
                            string text = packetReader.ReadString();
                            Program.BroadcastPlainMessage(text, senderUid);
                            break;

                        case ServerPacketOpCode.EncryptedMessage:
                            Guid encSender = packetReader.ReadUid();
                            Guid encRecipient = packetReader.ReadUid();
                            byte[] cipher = packetReader.ReadBytesWithLength();
                            string cipherB64 = Convert.ToBase64String(cipher);
                            Program.RelayEncryptedMessageToAUser(cipherB64, encSender, encRecipient);
                            break;

                        case ServerPacketOpCode.DisconnectNotify:
                            Guid discUid = packetReader.ReadUid();
                            Program.BroadcastDisconnect(discUid.ToString());
                            break;

                        case ServerPacketOpCode.DisconnectClient:
                            ClientSocket.Close();
                            Program.BroadcastDisconnect(UID.ToString());
                            return;

                        default:
                            ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn, Username, $"{opcode}");
                            break;
                    }
                }
                catch (EndOfStreamException)
                {
                    ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
                }
                catch (IOException ioe)
                {
                    ServerLogger.LogLocalized("IOError", ServerLogLevel.Info, Username, ioe.Message);
                }
                catch (Exception ex)
                {
                    ServerLogger.LogLocalized("PacketLoopError", ServerLogLevel.Error, Username, ex.Message);
                }
                finally
                {
                    CleanupAfterDisconnect();
                }
            }
        }
    }
}

