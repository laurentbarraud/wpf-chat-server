/// <file>PacketBuilder.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 21th, 2025</date>

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
    }
}

