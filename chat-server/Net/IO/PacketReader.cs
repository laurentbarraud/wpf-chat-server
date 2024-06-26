﻿/// <file>PacketReader.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.4</version>
/// <date>June 26th, 2024</date>

using System.Net.Sockets;
using System.Text;


namespace chat_server.Net.IO
{
    class PacketReader : BinaryReader
    {
        private NetworkStream _ns;
        public PacketReader(NetworkStream ns) : base(ns)
        {
            _ns = ns;           
        }

        /// <summary>
        /// This function will read the payload part of the packet
        /// </summary>
        /// <returns>a string containing the message</returns>
        public string ReadMessage()
        {
            byte[] msgBuffer;

            // Reads the first 4-byte and
            // stores it as the length of the message
            var length = ReadInt32();

            msgBuffer = new byte[length];

            // Reads data from the network stream and
            // stores it to a byte array (msgBuffer)
            // from the first byte to the length of the message
            _ns.Read(msgBuffer, 0, length);

            var msg = Encoding.ASCII.GetString(msgBuffer);
            return msg;
        }
    }
}
