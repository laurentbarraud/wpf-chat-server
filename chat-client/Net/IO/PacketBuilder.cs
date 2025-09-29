/// <file>PacketBuilder.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 29th, 2025</date>

using chat_client.Net;
using System;
using System.IO;
using System.Net;
using System.Text;

namespace chat_client.Net
{
    /// <summary>
    /// Constructs protocol-compliant packets for the chat application.
    /// Writes an opcode followed by structured fields in network byte order.
    /// Accumulates data in a MemoryStream and exposes the final byte array.
    /// </summary>
    public class PacketBuilder
    {
        private readonly MemoryStream _ms;

        /// <summary>
        /// Instantiates a new PacketBuilder with an empty buffer.
        /// </summary>
        public PacketBuilder()
        {
            _ms = new MemoryStream();
        }

        /// <summary>
        /// Writes the packet opcode byte.
        /// </summary>
        /// <param name="opcode">The single-byte opcode identifier.</param>
        public void WriteOpCode(byte opcode) =>
            _ms.WriteByte(opcode);

        /// <summary>
        /// Writes a 16-byte UID.
        /// </summary>
        /// <param name="uid">The UID to serialize.</param>
        public void WriteUid(Guid uid)
        {
            byte[] bytes = uid.ToByteArray();
            _ms.Write(bytes, 0, bytes.Length);
        }

        /// <summary>
        /// Writes a length-prefixed UTF-8 string.
        /// </summary>
        /// <param name="s">The string to serialize.</param>
        public void WriteString(string s)
        {
            byte[] data = Encoding.UTF8.GetBytes(s);
            byte[] lenBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(data.Length));
            _ms.Write(lenBytes, 0, lenBytes.Length);
            _ms.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Writes a length-prefixed byte-array payload.
        /// </summary>
        /// <param name="data">The raw bytes to serialize.</param>
        public void WriteBytes(byte[] data)
        {
            byte[] lenBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(data.Length));
            _ms.Write(lenBytes, 0, lenBytes.Length);
            _ms.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Returns the constructed packet as a byte array.
        /// </summary>
        /// <returns>The full packet ready for network transmission.</returns>
        public byte[] GetPacketBytes() =>
            _ms.ToArray();


        // ——— Models A–F ———

        /// <summary>
        /// Model A: Writes the user-connected packet (opcode + UID + username).
        /// </summary>
        public void WriteUserConnected(Guid uid, string username)
        {
            WriteOpCode((byte)ClientPacketOpCode.ConnectionBroadcast);
            WriteUid(uid);
            WriteString(username);
        }

        /// <summary>
        /// Model A: Writes the user-disconnected packet (opcode + UID + username).
        /// </summary>
        public void WriteUserDisconnected(Guid uid, string username)
        {
            WriteOpCode((byte)ClientPacketOpCode.DisconnectNotify);
            WriteUid(uid);
            WriteString(username);
        }

        /// <summary>
        /// Model B: Writes the public-key request packet (opcode + sender UID + target UID).
        /// </summary>
        public void WritePublicKeyRequest(Guid senderUid, Guid targetUid)
        {
            WriteOpCode((byte)ClientPacketOpCode.PublicKeyRequest);
            WriteUid(senderUid);
            WriteUid(targetUid);
        }

        /// <summary>
        /// Model C: Writes the plain-text message packet (opcode + sender UID + message).
        /// </summary>
        public void WritePlainMessage(Guid senderUid, string message)
        {
            WriteOpCode((byte)ClientPacketOpCode.PlainMessage);
            WriteUid(senderUid);
            WriteString(message);
        }

        /// <summary>
        /// Model D: Writes the public-key response packet (opcode + sender UID + public key).
        /// </summary>
        public void WritePublicKeyResponse(Guid senderUid, string publicKeyBase64)
        {
            WriteOpCode((byte)ClientPacketOpCode.PublicKeyResponse);
            WriteUid(senderUid);
            WriteString(publicKeyBase64);
        }

        /// <summary>
        /// Model E: Writes the encrypted-message packet (opcode + sender UID + encrypted payload).
        /// </summary>
        public void WriteEncryptedMessage(Guid senderUid, byte[] encryptedPayload)
        {
            WriteOpCode((byte)ClientPacketOpCode.EncryptedMessage);
            WriteUid(senderUid);
            WriteBytes(encryptedPayload);
        }

        /// <summary>
        /// Model F: Writes the server-disconnect packet (opcode + recipient UID).
        /// </summary>
        public void WriteServerDisconnect(Guid recipientUid)
        {
            WriteOpCode((byte)ClientPacketOpCode.DisconnectClient);
            WriteUid(recipientUid);
        }
    }
}

