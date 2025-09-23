/// <file>PacketBuilder.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 23th, 2025</date>

using System.Text;

namespace chat_server.Net.IO
{
    public class PacketBuilder
    {
        MemoryStream _ms;
        public PacketBuilder()
        {
            _ms = new MemoryStream();
        }

        // Writes an opcode at the beginning of the packet
        // to identify the type of package
        public void WriteOpCode(byte opcode)
        {
            _ms.WriteByte(opcode);
        }

        public void WriteMessage(string msg)
        {
            // Convert the message to UTF-8 bytes (supports emojis and all Unicode characters)
            var msgBytes = Encoding.UTF8.GetBytes(msg);

            // Write the length of the byte array (not character count!)
            var msgLength = msgBytes.Length;
            _ms.Write(BitConverter.GetBytes(msgLength));

            // Write the actual message bytes
            _ms.Write(msgBytes);
        }

        public byte[] GetPacketBytes()
        {
            return _ms.ToArray();
        }
    }
}
