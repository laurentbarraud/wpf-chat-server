/// <file>PacketExtensions.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 27th, 2025</date>

namespace chat_server.Net.IO 
{
    /// <summary>
    /// Provides extension methods for PacketBuilder and PacketReader
    /// to work directly with opcode enums instead of raw bytes.
    /// </summary>
    public static class PacketExtensions
    {
        /// <summary>
        /// Writes the given opcode enum as a single byte.
        /// </summary>
        public static void WriteOpCode(this PacketBuilder _packetBuilder, ServerPacketOpCode _opCode)
        {
            _packetBuilder.WriteOpCode((byte)_opCode);
        }

        /// <summary>
        /// Reads a single byte from the stream and casts it to ClientOpCode.
        /// </summary>
        public static ServerPacketOpCode ReadOpCode(this PacketReader _packetReader)
        {
            return (ServerPacketOpCode)_packetReader.ReadByte();
        }
    }
}

