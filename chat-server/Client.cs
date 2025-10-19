/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 18th, 2025</date>

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
            Program.BroadcastDisconnectNotify(UID.ToString());
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
                    /// <summary>
                    /// Reads next framed packet
                    /// </summary>
                    int bodyLength = packetReader.ReadInt32NetworkOrder();
                    if (bodyLength <= 0)
                        continue;

                    /// <summary >
                    /// Reads opcode
                    /// <summary >
                    var opcode = (ServerPacketOpCode)packetReader.ReadByte();

                    switch (opcode)
                    {
                        case ServerPacketOpCode.RosterBroadcast:
                            Program.BroadcastRoster();
                            break;

                        case ServerPacketOpCode.PublicKeyRequest:
                            /// <summary>
                            /// PublicKeyRequest payload:
                            ///  [16-byte requester UID]
                            ///  [16-byte target UID]
                            /// </ summary >
                            Guid requestSender = packetReader.ReadUid();
                            Guid requestTarget = packetReader.ReadUid();
                            Program.RelayPublicKeyRequest(requestSender, requestTarget);
                            break;

                        case ServerPacketOpCode.PublicKeyResponse:
                            Guid respSenderUid = packetReader.ReadUid();
                            string publicKeyB64 = packetReader.ReadString();
                            Guid recipientUid = packetReader.ReadUid();
                            Program.RelayPublicKeyToUser(respSenderUid, publicKeyB64, recipientUid);
                            break;

                        case ServerPacketOpCode.PlainMessage:
                            /// <summary>
                            ///  Plain-text message payload format:
                            ///  [16-byte sender UID]
                            ///  [16-byte recipient UID placeholder]
                            ///  [4-byte text length][UTF-8 text bytes]
                            /// </summary>
                            Guid senderUid = packetReader.ReadUid();
                            _ = packetReader.ReadUid();                  // discard recipient UID placeholder
                            string text = packetReader.ReadString();   // reads length+UTF-8 bytes
                            Program.BroadcastPlainMessage(text, senderUid);
                            break;

                        case ServerPacketOpCode.EncryptedMessage:
                            Guid encSenderUid = packetReader.ReadUid();
                            Guid encRecipientUid = packetReader.ReadUid();
                            /// <summary> 
                            /// Reads the encrypted message payload (ciphertext)
                            /// into a byte array 
                            /// </summary>
                            byte[] ciphertext = packetReader.ReadBytesWithLength();
                            /// <summary> 
                            /// Converts the raw ciphertext to a Base64
                            /// string for safe transmission 
                            /// </summary>
                            string ciphertextB64 = Convert.ToBase64String(ciphertext);
                            Program.RelayEncryptedMessageToAUser(ciphertextB64, encSenderUid, encRecipientUid);
                            break;

                        case ServerPacketOpCode.DisconnectNotify:
                            /// <summary>
                            /// Reads a DisconnectNotify:
                            /// [16-byte disconnecting UID]
                            /// </summary>
                            Guid disconnectedUid = packetReader.ReadUid();
                            Program.BroadcastDisconnectNotify(disconnectedUid.ToString());
                            break;

                        default:
                            ServerLogger.LogLocalized("UnknownOpcode", ServerLogLevel.Warn,
                                Username, $"{opcode}");
                            break;
                    }
                }
                catch (EndOfStreamException)
                {
                    /// <summary>
                    /// User closed client application or explicitly disconnected
                    /// </summary>
                    ServerLogger.LogLocalized("StreamClosed", ServerLogLevel.Info, Username);
                    break;
                }
                catch (IOException ioe)
                {   /// <summary >
                    /// Network I/O error
                    /// </summary>
                    ServerLogger.LogLocalized("IOError", ServerLogLevel.Info, Username, ioe.Message);
                    break;
                }
                catch (Exception ex)
                {
                    /// <summary>
                    /// Logs unexpected error and exits loop
                    /// </ summary >
                    ServerLogger.LogLocalized("PacketLoopError", ServerLogLevel.Error, Username, ex.Message);
                    break;
                }
            }

            /// <summary> 
            /// Once the read loop ends, performs cleanup
            /// </summary>
            CleanupAfterDisconnect();
        }
    }
}

