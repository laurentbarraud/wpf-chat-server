/// <file>PacketReader.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 2nd, 2026</date>

using System;
using System.Text;

namespace chat_protocol.Net.IO
{
    /// <summary>
    /// Async-first framed packet reader.
    /// Reads a 4-byte network-order length prefix, then the framed body.
    /// Exposes asynchronous read methods that guarantee exact byte consumption.
    /// Sealed to enforce composition over inheritance and preserve protocol invariants.
    /// </summary>
    public sealed class PacketReader
    {
        private readonly Stream _stream;

        /// <summary>
        /// Maximum allowed length for generic length-prefixed payloads (tunable).
        /// </summary>
        private const int DefaultMaxLengthPrefixedBytes = 65_536; // 64 KB

        /// <summary>
        /// Absolute maximum allowed frame size (protects against excessive allocation).
        /// </summary>
        private const int AbsoluteMaxFrameSize = 10 * 1024 * 1024; // 10 MB

        /// <summary>
        /// Gets the underlying stream used for reads.
        /// </summary>
        private Stream BaseStream => _stream;

        /// <summary>
        /// Creates a new PacketReader over the provided stream. 
        /// The stream must remain open for the reader's lifetime.
        /// </summary>
        public PacketReader(Stream stream)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        }

        /// <summary>
        /// Reads a single byte asynchronously from the underlying stream.
        /// </summary>
        public async Task<byte> ReadByteAsync(CancellationToken cancellationToken = default)
        {
            var buf = await ReadExactAsync(BaseStream, 1, cancellationToken).ConfigureAwait(false);
            return buf[0];
        }

        /// <summary>
        /// Reads a length-prefixed byte array.
        /// The length is a 4-byte network-order integer and is validated 
        /// against the provided maximum.
        /// </summary>
        public async Task<byte[]> ReadBytesWithLengthAsync(int? maxAllowed = null, CancellationToken cancellationToken = default)
        {
            int max = maxAllowed ?? DefaultMaxLengthPrefixedBytes;
            int lengthHost = await ReadInt32NetworkOrderAsync(cancellationToken).ConfigureAwait(false);

            if (lengthHost < 0 || lengthHost > max)
                throw new InvalidDataException($"Length-prefixed payload invalid: {lengthHost}");

            if (lengthHost == 0) return Array.Empty<byte>();

            return await ReadExactAsync(BaseStream, lengthHost, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads exactly 'byteCount' bytes from the provided stream asynchronously.
        /// Throws IOException if the remote peer closes the stream before all bytes are read.
        /// </summary>
        public static async Task<byte[]> ReadExactAsync(Stream sourceStream, int byteCount, CancellationToken cancellationToken = default)
        {
            if (sourceStream == null)
                throw new ArgumentNullException(nameof(sourceStream));

            if (byteCount <= 0)
                return Array.Empty<byte>();

            var resultBuffer = new byte[byteCount];
            int bytesReadTotal = 0;

            while (bytesReadTotal < byteCount)
            {
                // Attempt to read the remaining bytes
                int bytesRead = await sourceStream
                    .ReadAsync(resultBuffer, bytesReadTotal, byteCount - bytesReadTotal, cancellationToken)
                    .ConfigureAwait(false);

                if (bytesRead == 0)
                    throw new IOException("Remote socket closed before completing ReadExactAsync.");

                bytesReadTotal += bytesRead;
            }

            return resultBuffer;
        }

        /// <summary>
        /// Reads a framed packet body: a 4-byte network-order (big-endian) length prefix 
        /// followed by that many bytes. Validates the frame length against an absolute maximum 
        /// to avoid resource exhaustion.
        /// </summary>
        public async Task<byte[]> ReadFramedBodyAsync(CancellationToken cancellationToken = default)
        {
            // Read the 4-byte length prefix in big-endian order and convert to host integer.
            int packetLength = await ReadInt32NetworkOrderAsync(cancellationToken).ConfigureAwait(false);

            // Validate the length to prevent invalid or maliciously large frames.
            if (packetLength <= 0 || packetLength > AbsoluteMaxFrameSize)
                throw new InvalidDataException($"Framed body length invalid: {packetLength}");

            // Read exactly 'packetLength' bytes from the stream to get the full packet body.
            byte[] packetBody = await ReadExactAsync(BaseStream, packetLength, cancellationToken).ConfigureAwait(false);

            return packetBody;
        }


        /// <summary>
        /// Reads a 4-byte big-endian integer from the stream and returns it in host byte order.
        /// Diagnostic: logs the raw 4 bytes read as READ_HEADER=xx-xx-xx-xx (Debug).
        /// </summary>
        public async Task<int> ReadInt32NetworkOrderAsync(CancellationToken cancellationToken = default)
        {
            // Reads exactly 4 bytes from the stream to form the packet length header.
            byte[] headerBytes = await ReadExactAsync(BaseStream, 4, cancellationToken).ConfigureAwait(false);

            // Composes the integer value directly in big-endian order.
            int packetLength =
                (headerBytes[0] << 24) |
                (headerBytes[1] << 16) |
                (headerBytes[2] << 8) |
                (headerBytes[3]);

            return packetLength;
        }

        /// <summary>
        /// Reads a UTF-8 length-prefixed string (4-byte length in network order).
        /// </summary>
        public async Task<string> ReadStringAsync(CancellationToken cancellationToken = default)
        {
            var data = await ReadBytesWithLengthAsync(DefaultMaxLengthPrefixedBytes, cancellationToken).ConfigureAwait(false);
            return Encoding.UTF8.GetString(data);
        }

        /// <summary>
        /// Reads a 16-byte GUID (UUID) in raw binary format.
        /// </summary>
        public async Task<Guid> ReadUidAsync(CancellationToken cancellationToken = default)
        {
            var uidBytes = await ReadExactAsync(BaseStream, 16, cancellationToken).ConfigureAwait(false);
            return new Guid(uidBytes);
        }
    }
}
