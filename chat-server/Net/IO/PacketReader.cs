/// <file>PacketReader.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 7th, 2025</date>

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace chat_server.Net.IO
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
        /// Creates a new PacketReader over the provided stream. 
        /// The stream must remain open for the reader's lifetime.
        /// </summary>
        public PacketReader(Stream stream)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        }

        /// <summary>
        /// Gets the underlying stream used for reads.
        /// </summary>
        private Stream BaseStream => _stream;

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

            if (lengthHost <= 0 || lengthHost > max)
                throw new InvalidDataException($"Length-prefixed payload invalid: {lengthHost}");

            return await ReadExactAsync(BaseStream, lengthHost, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads exactly 'count' bytes from the provided stream asynchronously.
        /// Throws IOException if the remote peer closes the stream during the read.
        /// </summary>
        public static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken cancellationToken = default)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }
            
            if (count <= 0)
            {
                return Array.Empty<byte>();
            } 

            var buffer = new byte[count];
            int offset = 0;

            while (offset < count)
            {
                int read;
                try
                {
                    read = await stream.ReadAsync(buffer, offset, count - offset, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception)
                {
                    throw;
                }

                if (read == 0)
                    throw new IOException("Remote socket closed during ReadExactAsync.");

                offset += read;
            }

            return buffer;
        }

        /// <summary>
        /// Reads a framed packet body: a 4-byte network-order length followed by that many bytes.
        /// Validates the frame length against an absolute maximum to avoid resource exhaustion.
        /// </summary>
        public async Task<byte[]> ReadFramedBodyAsync(CancellationToken cancellationToken = default)
        {
            int lengthHost = await ReadInt32NetworkOrderAsync(cancellationToken).ConfigureAwait(false);

            if (lengthHost <= 0 || lengthHost > AbsoluteMaxFrameSize)
                throw new InvalidDataException($"Framed body length invalid: {lengthHost}");

            return await ReadExactAsync(BaseStream, lengthHost, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads a 4-byte big-endian integer from the stream and returns it in host byte order.
        /// </summary>
        public async Task<int> ReadInt32NetworkOrderAsync(CancellationToken cancellationToken = default)
        {
            var netBytes = await ReadExactAsync(BaseStream, 4, cancellationToken).ConfigureAwait(false);
            int netValue = BitConverter.ToInt32(netBytes, 0);
            return IPAddress.NetworkToHostOrder(netValue);
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
