using System;
using System.Security.Cryptography;
using YoloDev.Skiba.Impl;

namespace YoloDev.Skiba.Kdf
{
    /// <summary>
    /// Concepts from:
	/// http://csrc.nist.gov/publications/nistpubs/800-108/sp800-108.pdf
	/// http://referencesource.microsoft.com/#System.Web/Security/Cryptography/SP800_108.cs
    /// </summary>
    public static class SP800_108_Ctr
    {
        const int COUNTER_LENGTH = sizeof(uint);
        const int KEY_LENGTH = sizeof(int);

        internal static byte[] CreateBuffer(ArraySegment<byte>? label, ArraySegment<byte>? context, int keyLengthInBits)
        {
            int labelLength = (label != null) ? label.Value.Count : 0;
            int contextLength = (context != null) ? context.Value.Count : 0;
            int bufferLength = (COUNTER_LENGTH /* counter */) + (labelLength + 1 /* label + 0x00 */) + (contextLength /* context */) + (KEY_LENGTH /* [L]_2 */);
            var buffer = new byte[bufferLength];

            // store label, if any
            if (labelLength > 0)
                Buffer.BlockCopy(label.Value.Array, label.Value.Offset, buffer, COUNTER_LENGTH, labelLength);

            // store context, if any
            if (contextLength > 0)
                Buffer.BlockCopy(context.Value.Array, context.Value.Offset, buffer, COUNTER_LENGTH + labelLength + 1, contextLength);

            // store key length
            new IntStruct { IntValue = keyLengthInBits }.ToBEBytes(buffer, bufferLength - COUNTER_LENGTH);
            return buffer;
        }

        public static void DeriveKey(Func<HMAC> hmacFactory, byte[] key, ArraySegment<byte>? label, ArraySegment<byte>? context, ArraySegment<byte> derivedOutput, uint counter = 1)
        {
            using (var hmac = hmacFactory())
            {
                hmac.Key = key;
                var buffer = CreateBuffer(label: label, context: context, keyLengthInBits: derivedOutput.Count * 8);
                DeriveKey(hmac, buffer.AsArraySegment(), derivedOutput, counter);
            }
        }

        internal static void DeriveKey(HMAC keyedHmac, ArraySegment<byte> bufferSegment, ArraySegment<byte> derivedOutput, uint counter = 1)
        {
            int derivedOutputCount = derivedOutput.Count, derivedOutputOffset = derivedOutput.Offset;
            byte[] K_i = null;
            checked
            {
                // Calculate each K_i value and copy the leftmost bits to the output buffer as appropriate.
                for (var counterStruct = new IntStruct { UintValue = counter }; derivedOutputCount > 0; ++counterStruct.UintValue)
                {
                    counterStruct.ToBEBytes(bufferSegment.Array, bufferSegment.Offset); // update the counter within the buffer
                    K_i = keyedHmac.ComputeHash(bufferSegment.Array, bufferSegment.Offset, bufferSegment.Count);

                    // copy the leftmost bits of K_i into the output buffer
                    int numBytesToCopy = Math.Min(derivedOutputCount, K_i.Length);
                    Buffer.BlockCopy(K_i, 0, derivedOutput.Array, derivedOutputOffset, numBytesToCopy);
                    derivedOutputOffset += numBytesToCopy;
                    derivedOutputCount -= numBytesToCopy;
                }// for
            }// checked
            if (K_i != null) Array.Clear(K_i, 0, K_i.Length);
        }
    }
}
