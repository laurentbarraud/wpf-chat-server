/// <file>PacketReader.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 27th, 2025</date>

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace chat_server.Net.IO
{
    /// <summary>
    /// Provides robust, framed parsing of protocol packets from a stream.
    /// Reads a 4-byte network-order length prefix, then the framed body.
    /// Exposes safe, single-responsibility Read methods that operate on
    /// the current stream position and ensure exact byte consumption.
    /// </summary>
    public class PacketReader
    {
        private readonly Stream _stream;

        /// <summary>
        /// Exposes the underlying stream for internal helpers.
        /// Kept as a property to avoid duplicating field access and to make intent explicit.
        /// </summary>
        private Stream BaseStream => _stream;

        /// <summary>
        /// Instantiates a new PacketReader over the given stream.
        /// </summary>
        public PacketReader(Stream input)
        {
            _stream = input ?? throw new ArgumentNullException(nameof(input));
        }

        /// <summary>
        /// Instantiates a new PacketReader over the given NetworkStream.
        /// </summary>
        public PacketReader(NetworkStream networkStream) : this((Stream)networkStream) { }

        /// <summary>
        /// Reads a single byte.
        /// </summary>
        public byte ReadByte()
        {
            return ReadExact(1)[0];
        }

        /// <summary>
        /// Reads a length-prefixed byte array from the stream and returns the payload.
        /// </summary>
        /// <returns>Payload bytes, or an empty array on invalid length or read failure.</returns>
        public byte[] ReadBytesWithLength()
        {
            const int MaxAllowedLength = 65_536; // 64 KB upper sanity bound

            // Reads the 4-byte length prefix in network byte order (big-endian).
            int lengthNetworkOrder = ReadInt32NetworkOrder();

            // Converts the network-order length to host byte order.
            int lengthHostOrder = System.Net.IPAddress.NetworkToHostOrder(lengthNetworkOrder);

            // Validates length
            if (lengthHostOrder <= 0 || lengthHostOrder > MaxAllowedLength)
            {
                // Silent failure : returns an empty payload on invalid values 
                return Array.Empty<byte>();
            }

            // Reads exactly lengthHostOrder bytes.
            try
            {
                return ReadExact(lengthHostOrder);
            }
            catch
            {
                // Silent failure on read error: return empty payload to avoid bubbling exceptions.
                return Array.Empty<byte>();
            }
        }

        /// <summary>
        /// Reads exactly count bytes from the underlying stream and returns them.
        /// On early EOF or I/O error, returns an empty array instead of throwing.
        /// </summary>
        /// <returns>Byte array of length 'count' filled with data read, or empty array on failure.</returns>
        public byte[] ReadExact(int count)
        {
            if (count <= 0)
                return Array.Empty<byte>();

            // Holds the bytes read from the stream
            var buffer = new byte[count];
            // Tracks how many bytes have been written into 'buffer' so far; next write starts at this index.
            int offset = 0;

            // Loops until the requested number of bytes has been read or a fatal read occurs.
            try
            {
                while (offset < count)
                {
                    // Reads from the base stream; returns number of bytes read or 0 on EOF.
                    int read = BaseStream.Read(buffer, offset, count - offset);
                    if (read == 0)
                    {
                        // Silent failure on EOF: return empty payload to let caller decide.
                        return Array.Empty<byte>();
                    }
                    offset += read;
                }

                // Returns the full buffer when successful.
                return buffer;
            }
            catch
            {
                // Silent failure on any I/O exception: return empty payload.
                return Array.Empty<byte>();
            }
        }

        /// <summary>
        /// Reads a 4-byte big-endian integer and converts to host order.
        /// </summary>
        public int ReadInt32NetworkOrder()
        {
            byte[] netBytes = ReadExact(4);
            int netValue = BitConverter.ToInt32(netBytes, 0);
            return IPAddress.NetworkToHostOrder(netValue);
        }

        /// <summary>
        /// Reads a length‐prefixed UTF8 string.
        /// </summary>
        public string ReadString()
        {
            byte[] data = ReadBytesWithLength();
            return Encoding.UTF8.GetString(data);
        }

        /// <summary>
        /// Reads a 16‐byte UID (Guid).
        /// </summary>
        public Guid ReadUid()
        {
            byte[] uidBytes = ReadExact(16);
            return new Guid(uidBytes);
        }
    }
}

