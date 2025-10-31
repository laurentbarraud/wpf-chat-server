﻿/// <file>PacketBuilder.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 31th, 2025</date>

using System;
using System.IO;
using System.Net;
using System.Text;

namespace chat_client.Net
{
    /// <summary>
    /// Builds protocol-compliant packet bodies.
    /// Accumulates fields into an internal MemoryStream and exposes the raw payload bytes.
    /// Provides an async helper to write a framed packet (4-byte big-endian length prefix + payload)
    /// to a destination stream atomically.
    /// </summary>
    public sealed class PacketBuilder
    {
        private readonly MemoryStream _buffer;

        /// <summary>
        /// Creates a new PacketBuilder with an empty internal buffer.
        /// </summary>
        public PacketBuilder()
        {
            _buffer = new MemoryStream();
        }

        /// <summary>
        /// Appends the given opcode byte to the packet body.
        /// </summary>
        /// <param name="opcode">Single-byte opcode.</param>
        public void WriteOpCode(byte opcode)
        {
            _buffer.WriteByte(opcode);
        }

        /// <summary>
        /// Appends a 16-byte GUID (UUID) in raw binary format to the packet body.
        /// </summary>
        /// <param name="uid">GUID to write.</param>
        public void WriteUid(Guid uid)
        {
            var bytes = uid.ToByteArray();
            _buffer.Write(bytes, 0, bytes.Length);
        }

        /// <summary>
        /// Appends a length-prefixed UTF-8 string to the packet body.
        /// Length is written as a 4-byte big-endian integer (network order).
        /// </summary>
        /// <param name="value">String to serialize; non-null expected.</param>
        public void WriteString(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            var encoded = Encoding.UTF8.GetBytes(value);
            WriteBytesWithLength(encoded);
        }

        /// <summary>
        /// Appends a length-prefixed raw byte array to the packet body.
        /// Length is written as a 4-byte big-endian integer (network order).
        /// Accepts null to write a zero length prefix.
        /// </summary>
        /// <param name="data">Byte array to serialize, or null to indicate zero length.</param>
        public void WriteBytesWithLength(byte[]? data)
        {
            int len = data?.Length ?? 0;
            var lenPrefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(len));
            _buffer.Write(lenPrefix, 0, lenPrefix.Length);
            if (len > 0)
                _buffer.Write(data!, 0, len);
        }

        /// <summary>
        /// Returns a copy of the current packet body bytes (no framing).
        /// Caller may mutate the returned array without affecting the builder.
        /// </summary>
        public byte[] GetPacketBytes()
        {
            return _buffer.ToArray();
        }

        /// <summary>
        /// Writes the framed packet (4-byte big-endian length prefix + current payload)
        /// to the provided stream using a single async write for the full buffer and a flush.
        /// This helper guarantees atomic write ordering from the application's perspective.
        /// </summary>
        /// <param name="destination">The stream to write the framed packet to.</param>
        /// <param name="cancellationToken">Cancellation token for the write operation.</param>
        public async Task WriteFramedPacketAsync(Stream destination, CancellationToken cancellationToken = default)
        {
            if (destination == null) throw new ArgumentNullException(nameof(destination));

            // Prepares payload and frame header
            byte[] payload = GetPacketBytes();
            int payloadLength = payload.Length;

            int netOrder = IPAddress.HostToNetworkOrder(payloadLength);
            var header = BitConverter.GetBytes(netOrder);

            // Combines header + payload into a single buffer to perform a single WriteAsync if desired.
            // Allocates only once: header (4 bytes) + payload
            var framed = new byte[4 + payloadLength];
            Buffer.BlockCopy(header, 0, framed, 0, 4);
            if (payloadLength > 0)
                Buffer.BlockCopy(payload, 0, framed, 4, payloadLength);

            // Writes the full framed buffer and flush to ensure ordering
            await destination.WriteAsync(framed, 0, framed.Length, cancellationToken).ConfigureAwait(false);
            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Clears the internal buffer so the builder can be reused for another packet.
        /// </summary>
        public void Reset()
        {
            _buffer.SetLength(0);
            _buffer.Position = 0;
        }
    }
}

