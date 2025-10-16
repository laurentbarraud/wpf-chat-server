/// <file>PacketReader.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 16th, 2025</date>

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace chat_client.Net.IO
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
        /// Reads exactly count bytes from the underlying stream.
        /// Throws EndOfStreamException if the stream closes before count bytes are read.
        /// </summary>
        /// <param name="count">Number of bytes to read.</param>
        /// <returns>Byte array of length count.</returns>
        public byte[] ReadBytesExactFromStream(int count)
        {
            if (count <= 0) return Array.Empty<byte>();

            byte[] buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = BaseStream.Read(buffer, read, count - read);
                if (n == 0)
                    throw new EndOfStreamException("Stream closed while reading exact bytes");
                read += n;
            }
            return buffer;
        }

        /// <summary>
        /// Reads a length‐prefixed byte array: 4-byte length (network order) + payload.
        /// </summary>
        public byte[] ReadBytesWithLength()
        {
            int length = ReadInt32NetworkOrder();
            return ReadExact(length);
        }

        /// <summary>
        /// Reads exactly count bytes from the stream.
        /// Throws EndOfStreamException if the stream closes too early.
        /// </summary>
        public byte[] ReadExact(int count)
        {
            if (count <= 0)
                return Array.Empty<byte>();

            var buffer = new byte[count];
            int reader = 0;
            while (reader < count)
            {
                int n = BaseStream.Read(buffer, reader, count - reader);
                if (n == 0)
                    throw new EndOfStreamException($"Stream closed while reading {count} bytes");
                reader += n;
            }

            return buffer;
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
        /// Packet model E: Reads an encrypted-message packet (sender UID + encrypted payload).
        /// </summary>
        /// <returns>Tuple of (sender UID, encrypted payload).</returns>
        public (Guid senderUid, byte[] encryptedPayload) ReadEncryptedMessage()
        {
            Guid sender = ReadUid();
            byte[] payload = ReadBytesWithLength();
            return (sender, payload);
        }

        /// <summary>
        /// Alias for reading the protocol opcode byte.
        /// </summary>
        public byte ReadOpCode() => ReadByte();

        /// <summary>
        /// Packet model C: Reads a plain-text message packet.
        /// Reads and returns the sender UID and the message text.
        /// Consumes the placeholder recipient UID written by the server and discards it,
        /// ensuring subsequent reads remain aligned with the stream.
        /// </summary>
        /// <returns>Tuple of (sender UID, message).</returns>
        public (Guid senderUid, string message) ReadPlainMessage()
        {
            // Read the sender UID written by the server
            Guid sender = ReadUid();

            // Read and discard the recipient UID that the server includes for all messages.
            // For broadcast/plain messages the server writes Guid.Empty; keep it here to
            // preserve stream alignment for the next field.
            _ = ReadUid();

            // Read the UTF-8 length-prefixed message string
            string msg = ReadString();

            return (sender, msg);
        }

        /// <summary>
        /// Packet model B: Reads a public-key request packet (sender UID + target UID).
        /// </summary>
        /// <returns>Tuple of (sender UID, target UID).</returns>
        public (Guid senderUid, Guid targetUid) ReadPublicKeyRequest()
        {
            Guid sender = ReadUid();
            Guid target = ReadUid();
            return (sender, target);
        }


        /// <summary>
        /// Packet model D: Reads a public-key response packet (sender UID + public key).
        /// </summary>
        /// <returns>Tuple of (sender UID, publicKeyBase64).</returns>
        public (Guid senderUid, string publicKeyBase64) ReadPublicKeyResponse()
        {
            Guid sender = ReadUid();
            string key = ReadString();
            return (sender, key);
        }

        /// <summary>
        /// Packet model F: Reads a server-disconnect packet (recipient UID).
        /// </summary>
        /// <returns>The UID of the client to disconnect.</returns>
        public Guid ReadServerDisconnect() =>
            ReadUid();

        /// <summary>
        /// Packet model A: Reads a user-connected packet (UID + username).
        /// </summary>
        /// <returns>Tuple of (UID, username).</returns>
        public (Guid uid, string username) ReadUserConnected()
        {
            Guid uid = ReadUid();
            string username = ReadString();
            return (uid, username);
        }

        /// <summary>
        /// Packet model A: Reads a user-disconnected packet (UID + username).
        /// </summary>
        /// <returns>Tuple of (UID, username).</returns>
        public (Guid uid, string username) ReadUserDisconnected()
        {
            Guid uid = ReadUid();
            string username = ReadString();
            return (uid, username);
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

