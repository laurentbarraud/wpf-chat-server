/// <file>PacketReader.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 27th, 2025</date>

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace chat_client.Net
{
    /// <summary>
    /// Parses incoming protocol packets from a NetworkStream.
    /// Reads an opcode byte, then structured fields in network byte order.
    /// Exposes dedicated ReadXxx methods for each packet model.
    /// </summary>
    public class PacketReader : BinaryReader
    {
        /// <summary>
        /// Instantiates a new PacketReader over the given network stream.
        /// </summary>
        public PacketReader(NetworkStream ns) : base(ns) { }

        /// <summary>
        /// Reads the packet opcode byte.
        /// </summary>
        /// <returns>The single-byte opcode identifier.</returns>
        public byte ReadOpCode() =>
            ReadByte();

        /// <summary>
        /// Reads a 16-byte UID.
        /// </summary>
        /// <returns>The deserialized UID.</returns>
        public Guid ReadUid()
        {
            byte[] uidBytes = ReadBytes(16);
            return new Guid(uidBytes);
        }

        /// <summary>
        /// Reads a length-prefixed byte-array payload.
        /// </summary>
        /// <returns>The raw payload bytes.</returns>
        public byte[] ReadBytesWithLength()
        {
            int len = IPAddress.NetworkToHostOrder(ReadInt32());
            return ReadBytes(len);
        }

        /// <summary>
        /// Reads a length-prefixed UTF-8 string.
        /// </summary>
        /// <returns>The deserialized string.</returns>
        public string ReadString()
        {
            byte[] data = ReadBytesWithLength();
            return Encoding.UTF8.GetString(data);
        }


        // ——— Models A–F ———

        /// <summary>
        /// Model A: Reads a user-connected packet (UID + username).
        /// </summary>
        /// <returns>Tuple of (UID, username).</returns>
        public (Guid uid, string username) ReadUserConnected()
        {
            Guid uid = ReadUid();
            string username = ReadString();
            return (uid, username);
        }

        /// <summary>
        /// Model A: Reads a user-disconnected packet (UID + username).
        /// </summary>
        /// <returns>Tuple of (UID, username).</returns>
        public (Guid uid, string username) ReadUserDisconnected()
        {
            Guid uid = ReadUid();
            string username = ReadString();
            return (uid, username);
        }

        /// <summary>
        /// Model B: Reads a public-key request packet (sender UID + target UID).
        /// </summary>
        /// <returns>Tuple of (sender UID, target UID).</returns>
        public (Guid senderUid, Guid targetUid) ReadPublicKeyRequest()
        {
            Guid sender = ReadUid();
            Guid target = ReadUid();
            return (sender, target);
        }

        /// <summary>
        /// Model C: Reads a plain-text message packet (sender UID + message).
        /// </summary>
        /// <returns>Tuple of (sender UID, message).</returns>
        public (Guid senderUid, string message) ReadPlainMessage()
        {
            Guid sender = ReadUid();
            string msg = ReadString();
            return (sender, msg);
        }

        /// <summary>
        /// Model D: Reads a public-key response packet (sender UID + public key).
        /// </summary>
        /// <returns>Tuple of (sender UID, publicKeyBase64).</returns>
        public (Guid senderUid, string publicKeyBase64) ReadPublicKeyResponse()
        {
            Guid sender = ReadUid();
            string key = ReadString();
            return (sender, key);
        }

        /// <summary>
        /// Model E: Reads an encrypted-message packet (sender UID + encrypted payload).
        /// </summary>
        /// <returns>Tuple of (sender UID, encrypted payload).</returns>
        public (Guid senderUid, byte[] encryptedPayload) ReadEncryptedMessage()
        {
            Guid sender = ReadUid();
            byte[] payload = ReadBytesWithLength();
            return (sender, payload);
        }

        /// <summary>
        /// Model F: Reads a server-disconnect packet (recipient UID).
        /// </summary>
        /// <returns>The UID of the client to disconnect.</returns>
        public Guid ReadServerDisconnect() =>
            ReadUid();
    }
}

