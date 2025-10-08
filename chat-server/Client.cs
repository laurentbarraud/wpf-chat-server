/// <file>Client.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 9th, 2025</date>

using chat_server.Helpers;
using chat_server.Net;
using chat_server.Net.IO;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace chat_server
{
    /// <summary>
    /// Continuously listens for incoming packets from the connected client.
    /// Dispatches each packet to the appropriate handler based on its opcode.
    /// Logs unknown opcodes and handles disconnection gracefully.
    /// </summary>
    public class Client
    {
        /// <summary>Gets or sets the client's display name.</summary>
        public string Username { get; set; }

        /// <summary>Gets or sets the client's unique identifier.</summary>
        public Guid UID { get; set; }

        /// <summary>Gets or sets the TCP connection for the client.</summary>
        public TcpClient ClientSocket { get; set; }

        /// <summary>Gets or sets the Base64-encoded RSA public key for encryption.</summary>
        public string? PublicKeyBase64 { get; set; }

        /// <summary>Gets or sets the raw DER bytes of the client's public key.</summary>
        public byte[]? PublicKeyDer { get; set; }

        private readonly PacketReader _packetReader;

        /// <summary>
        /// Initializes a new client instance, creates a PacketReader, and logs startup.
        /// </summary>
        public Client(TcpClient client, string username, Guid uid)
        {
            // Initialize to a safe inert reader to satisfy readonly invariant.
            // Per-packet parsing will still use PacketReader over MemoryStream created inside ListenForMessages.
            _packetReader = new PacketReader(new MemoryStream());

            ClientSocket = client;
            Username = username;
            UID = uid;

            // Logs that the client is now listening for messages
            Console.WriteLine($"[DEBUG] Listening for messages from {Username}...");
        }

        /// <summary>
        /// Cleans up after a client disconnects: closes the socket,
        /// removes from Program.Users, and broadcasts the event.
        /// </summary>
        private void CleanupAfterDisconnect()
        {
            // Closes the client socket
            try
            {
                ClientSocket.Close();
            }
            catch
            {
                // Swallows any exception on close
            }

            // Broadcasts the disconnection to remaining clients
            Program.BroadcastDisconnect(UID.ToString());

            // Removes this client from the global user list
            if (Program.Users.Remove(this))
            {
                Console.WriteLine($"[DEBUG] Removed user {Username} ({UID}) from user list");
            }
        }

        /// <summary>
        /// Reads framed packets from the client socket, 
        /// parses them using the protocol opcodes defined in Protocol.cs,
        /// and dispatches to server methods implemented on Program.
        /// Assumes 4-byte network-order length prefix framing.
        /// </summary>
        internal void ListenForMessages()
        {
            ServerLogger.Log($"Starting message loop for {Username} ({UID})", ServerLogLevel.Info);

            var netStream = ClientSocket.GetStream();
            var streamReader = new PacketReader(netStream);

            while (true)
            {
                try
                {
                    // Reads 4-byte length prefix from the network stream
                    byte[] lengthBuffer = streamReader.ReadBytesExactFromStream(4);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(lengthBuffer);

                    int packetLength = BitConverter.ToInt32(lengthBuffer, 0);
                    if (packetLength <= 0)
                        continue;

                    ServerLogger.Log($"PacketLength={packetLength} bytes from {Username}", ServerLogLevel.Debug);

                    // Reads the packet body into a byte array
                    byte[] packetBody = streamReader.ReadBytesExactFromStream(packetLength);

                    // Wraps the payload in a MemoryStream so PacketReader can consume it
                    using var payloadStream = new MemoryStream(packetBody);
                    var packetReader = new PacketReader(payloadStream);

                    // Reads opcode and logs it
                    byte rawOpCode = packetReader.ReadByte();
                    var opcode = (ServerPacketOpCode)rawOpCode;
                    ServerLogger.Log($"[MSG LOOP] Received opcode {opcode} ({rawOpCode}) from {Username}", ServerLogLevel.Debug);

                    switch (opcode)
                    {
                        case ServerPacketOpCode.Handshake:
                            {
                                // Handshake: Username; UserId; PublicKeyBase64
                                string clientUsername = packetReader.ReadString();
                                Guid clientUid = packetReader.ReadUid();
                                string publicKeyBase64 = packetReader.ReadString();

                                // Updates local client state
                                this.Username = clientUsername;
                                this.UID = clientUid;

                                // Broadcasts the updated list of connected users
                                Program.BroadcastConnection();

                                break;
                            }

                        case ServerPacketOpCode.ConnectionBroadcast:
                            {
                                // ConnectionBroadcast: UserId; Username; PublicKeyBase64
                                Guid newUserId = packetReader.ReadUid();
                                string newUserName = packetReader.ReadString();
                                string newUserKey = packetReader.ReadString();

                                // Broadcasts the updated list of connected users
                                Program.BroadcastConnection();

                                break;
                            }

                        case ServerPacketOpCode.PublicKeyRequest:
                            {
                                // PublicKeyRequest: RequesterUserId; TargetUserId
                                Guid requesterId = packetReader.ReadUid();
                                Guid targetId = packetReader.ReadUid();

                                // Forward request to Program routing helper
                                Program.RelayPublicKeyRequest(requesterId, targetId);
                                break;
                            }

                        case ServerPacketOpCode.PlainMessage:
                            {
                                // PlainMessage: SenderUserId; RecipientUserId; MessageText
                                Guid senderId = packetReader.ReadUid();
                                Guid recipient = packetReader.ReadUid(); // ignored for broadcast
                                string text = packetReader.ReadString();

                                // Logs before dispatching
                                ServerLogger.Log($"BroadcastPlainMessage invoked for sender {senderId}: '{text}'");

                                Program.BroadcastPlainMessage(text, senderId);
                                break;
                            }

                        case ServerPacketOpCode.PublicKeyResponse:
                            {
                                // PublicKeyResponse: ResponderUserId; PublicKeyBase64; RequesterUserId
                                Guid responderId = packetReader.ReadUid();
                                string responderKey = packetReader.ReadString();
                                Guid requesterId = packetReader.ReadUid();

                                // Send responder's public key only to the original requester
                                Program.RelayPublicKeyToUser(responderId, responderKey, requesterId);
                                break;
                            }

                        case ServerPacketOpCode.DisconnectNotify:
                            {
                                // DisconnectNotify: DisconnectingUserId
                                Guid disconnectingUser = packetReader.ReadUid();

                                // Notify all clients of the disconnection using Program helper
                                Program.BroadcastDisconnect(disconnectingUser.ToString());
                                break;
                            }

                        case ServerPacketOpCode.EncryptedMessage:
                            {
                                // EncryptedMessage: SenderUserId; RecipientUserId; CipherText
                                Guid senderId = packetReader.ReadUid();
                                Guid recipientId = packetReader.ReadUid();
                                byte[] cipher = packetReader.ReadBytesWithLength();

                                // Relay encrypted blob only to intended recipient
                                Program.RelayEncryptedMessageToAUser(Convert.ToBase64String(cipher), senderId, recipientId);
                                break;
                            }

                        case ServerPacketOpCode.DisconnectClient:
                            {
                                // DisconnectClient: TargetUserId
                                Guid targetId = packetReader.ReadUid();

                                // Program.Shutdown will perform connection teardown for this client context
                                Program.Shutdown();
                                break;
                            }

                        default:
                            {
                                ServerLogger.Log($"Unknown opcode {(byte)opcode} received from {Username} ({UID})", ServerLogLevel.Warn);
                                break;
                            }
                    }
                }
                catch (EndOfStreamException)
                {
                    ServerLogger.Log($"Stream closed unexpectedly for {Username} ({UID})", ServerLogLevel.Info);
                    CleanupAfterDisconnect();
                    break;
                }
                catch (IOException ex)
                {
                    ServerLogger.Log($"IO error while reading from {Username} ({UID}): {ex.Message}", ServerLogLevel.Info);
                    CleanupAfterDisconnect();
                    break;
                }
                catch (Exception ex)
                {
                    ServerLogger.Log($"Unhandled error in ListenForMessages for {Username} ({UID}): {ex}", ServerLogLevel.Error);
                    CleanupAfterDisconnect();
                }
            }
        }
    }
}


