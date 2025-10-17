/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 17th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using Microsoft.VisualBasic.ApplicationServices;
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

        /// <summary>
        /// Safely closes the client socket and broadcasts a disconnect notification.
        /// Safe to call multiple times; 
        /// </summary>
        private void CleanupAfterDisconnect()
        {
            try 
            {
                ClientSocket.Close(); 
            } 
            catch 
            { 
            }

            /// <summary>
            /// Removes the user from the server roster 
            /// and notifies all remaining clients.
            /// </summary>
            Program.BroadcastDisconnect(UID.ToString());
        }

        /// <summary>
        /// Main loop that reads framed packets from the client socket.
        /// Processes each ServerPacketOpCode until the client disconnects or an error occurs.
        /// Exits the loop on any disconnection or error, then calls CleanupAfterDisconnect() exactly once.
        /// </summary>
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
                            Program.BroadcastRoster();
                            break;

                        case ServerPacketOpCode.PublicKeyRequest:
                            Guid requestSenderUid = packetReader.ReadUid();
                            Guid requestTargetUid = packetReader.ReadUid();
                            Program.RelayPublicKeyRequest(requestSenderUid, requestTargetUid);
                            break;

                        case ServerPacketOpCode.PublicKeyResponse:
                            Guid respSenderUid = packetReader.ReadUid();
                            string publicKeyB64 = packetReader.ReadString();
                            Guid recipientUid = packetReader.ReadUid();
                            Program.RelayPublicKeyToUser(respSenderUid, publicKeyB64, recipientUid);
                            break;

                        case ServerPacketOpCode.PlainMessage:
                            Guid senderUid = packetReader.ReadUid();
                            /// <summary> Reads and discards the recipient UID placeholder (unused for broadcast) </summary> 
                            _ = packetReader.ReadUid(); 
                            string text = packetReader.ReadString();
                            Program.BroadcastPlainMessage(text, senderUid);
                            break;

                        case ServerPacketOpCode.EncryptedMessage:
                            Guid encSenderUid = packetReader.ReadUid();
                            Guid encRecipientUid = packetReader.ReadUid();
                            /// <summary> Reads the encrypted message payload (ciphertext) into a byte array </summary>
                            byte[] ciphertext = packetReader.ReadBytesWithLength();
                            /// <summary> Converts the raw ciphertext to a Base64 string for safe transmission </summary>
                            string ciphertextB64 = Convert.ToBase64String(ciphertext);
                            Program.RelayEncryptedMessageToAUser(ciphertextB64, encSenderUid, encRecipientUid);
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
                            ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn,
                                Username, $"{opcode}");
                            break;
                    }
                }
                catch (EndOfStreamException)
                {
                    // User closed client application or explicitly disconnected
                    ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
                    break;
                }
                catch (IOException ioe)
                {
                    // Network I/O error
                    ServerLogger.LogLocalized("IOError", ServerLogLevel.Info, Username, ioe.Message);
                    break;
                }
                catch (Exception ex)
                {
                    // Logs unexpected error and exits loop
                    ServerLogger.LogLocalized("PacketLoopError", ServerLogLevel.Error, Username, ex.Message);
                    break;
                }
            }

            // Once the read loop ends, performs cleanup
            CleanupAfterDisconnect();
        }
    }
}

