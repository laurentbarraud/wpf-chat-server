/// <file>PacketBuilder.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 12th, 2025</date>

using System;
using System.IO;
using System.Net;
using System.Text;

namespace chat_server.Net
{
    /// <summary>
    /// Constructs protocol-compliant packets for the chat application.
    /// Writes an opcode followed by structured fields in network byte order.
    /// Accumulates data in a MemoryStream and exposes the final byte array.
    /// </summary>
    public class PacketBuilder
    {
        private readonly MemoryStream _ms = new MemoryStream();

        /// <summary>
        /// Instantiates a new PacketBuilder with an empty buffer.
        /// </summary>
        public PacketBuilder()
        {
            _ms = new MemoryStream();
        }

        // <summary>
        /// Returns the current packet body as a byte array (no framing).
        /// </summary>
        public byte[] GetPacketBytes()
        {
            return _ms.ToArray();
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
        /// Writes a 4-byte network-order length prefix followed by the raw bytes into the packet body.
        /// </summary>
        public void WriteBytesWithLength(byte[]? data)
        {
            int len = data?.Length ?? 0;
            byte[] lenPrefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(len));
            _ms.Write(lenPrefix, 0, lenPrefix.Length);

            if (data != null && len > 0)
                _ms.Write(data, 0, len);
        }

        /// <summary>
        /// Writes the packet opcode byte.
        /// </summary>
        /// <param name="opcode">The single-byte opcode identifier.</param>
        public void WriteOpCode(byte opcode) =>
            _ms.WriteByte(opcode);

        /// <summary>
        /// Writes a length-prefixed UTF-8 string.
        /// </summary>
        /// <param name="stringToWrite">The string to serialize.</param>
        public void WriteString(string stringToWrite)
        {
            byte[] stringEncoded = Encoding.UTF8.GetBytes(stringToWrite);
            byte[] lenBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(stringEncoded.Length));
            _ms.Write(lenBytes, 0, lenBytes.Length);
            _ms.Write(stringEncoded, 0, stringEncoded.Length);
        }

        /// <summary>
        /// Writes a 16-byte UID.
        /// </summary>
        /// <param name="uid">The UID to serialize.</param>
        public void WriteUid(Guid uid)
        {
            byte[] bytes = uid.ToByteArray();
            _ms.Write(bytes, 0, bytes.Length);
        }

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

