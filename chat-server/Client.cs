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
            {
                throw new InvalidOperationException("Expected Handshake opcode");
            }

            Username = handshakeReader.ReadString();
            UID = handshakeReader.ReadUid();

            // Reads length-prefixed raw public key bytes (DER)
            int pkLen = handshakeReader.ReadInt32NetworkOrder();
            if (pkLen <= 0)
            {
                // Logs localized error, closes the socket and aborts client initialization
                ServerLogger.LogLocalized("ErrorPublicKeyLengthInvalid", ServerLogLevel.Warn, UID.ToString());
                try 
                { 
                    ClientSocket.Close();
                } 
                catch 
                {  
                
                }
                
                return;
            }

            PublicKeyDer = handshakeReader.ReadExact(pkLen);

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
            Program.BroadcastDisconnectNotify(UID);
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
                        continue;

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


