using System;
using System.Buffers.Binary;

public static class Framing
{
    /// <summary>
    /// Frames a raw payload with a 4-byte big-endian length prefix.
    /// The returned buffer layout is: [0..3] length BE, [4..] payload bytes.
    /// </summary>
    public static byte[] Frame(byte[] rawPayload)
    {
        if (rawPayload == null)
        {
            rawPayload = Array.Empty<byte>();
        }
        
        var rawPayloadLength = rawPayload.Length;
        var framedBuffer = new byte[4 + rawPayloadLength];

        // Write the 4-byte length prefix in big-endian order.
        // This ensures the receiver can parse the length unambiguously regardless of host endianness.
        // Use BinaryPrimitives to avoid manual BitConverter + Array.Reverse mistakes.
        BinaryPrimitives.WriteInt32BigEndian(framedBuffer.AsSpan(0, 4), rawPayloadLength);

        // Copy the raw payload bytes immediately after the 4-byte header.
        // This avoids extra allocations and keeps framing logic deterministic.
        Buffer.BlockCopy(rawPayload, 0, framedBuffer, 4, rawPayloadLength);

        return framedBuffer;
    }
}
