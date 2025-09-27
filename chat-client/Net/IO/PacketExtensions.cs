/// <file>PacketExtensions.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 27th, 2025</date>

using static chat_client.Net.Server;

namespace chat_client.Net.IO
{
    /// <summary>
    /// Helpers that let us use easy names instead of numbers
    /// when we write and read packet types.
    /// </summary>
    public static class PacketExtensions
    {
        /// <summary>
        /// Takes a packet type name (like PlainMessage)
        /// and writes its number into the packet.
        /// This way, the other side knows what kind of packet it is.
        /// </summary>
        public static void WriteOpCode(this PacketBuilder builder, ClientPacketOpCode code)
        {
            // Convert the name to its number and write it
            builder.WriteOpCode((byte)code);
        }

        /// <summary>
        /// Reads the first byte from incoming data,
        /// turns that number back into the packet type name,
        /// and returns it so we know what to do next.
        /// </summary>
        public static ClientPacketOpCode ReadOpCode(this PacketReader reader)
        {
            byte number = reader.ReadByte();
            return (ClientPacketOpCode)number;
        }
    }
}


