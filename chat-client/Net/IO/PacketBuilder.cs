/// <file>PacketBuilder.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.6.1</version>
/// <date>September 2nd, 2025</date>

using System.IO;
using System.Text;


namespace chat_client.Net.IO
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
            var msgLength = msg.Length;
            _ms.Write(BitConverter.GetBytes(msgLength));
            _ms.Write(Encoding.ASCII.GetBytes(msg));
        }

        public byte[] GetPacketBytes()
        {
            return _ms.ToArray();
        }
    }
}
