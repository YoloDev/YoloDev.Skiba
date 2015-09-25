using System.Runtime.InteropServices;
using System.Text;

namespace YoloDev.Skiba
{
    public static class Utils
    {
        public static readonly UTF8Encoding SafeUTF8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        [StructLayout(LayoutKind.Explicit)]
        struct Union
        {
            [FieldOffset(0)]
            public byte[] Bytes;

            [FieldOffset(0)]
            public long[] Longs;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="dest"></param>
        /// <param name="destOffset"></param>
        /// <param name="left"></param>
        /// <param name="leftOffset"></param>
        /// <param name="right"></param>
        /// <param name="rightOffset"></param>
        /// <param name="byteCount"></param>
        public static void Xor(byte[] dest, int destOffset, byte[] left, int leftOffset, byte[] right, int rightOffset, int byteCount)
        {
            int i = 0;
            if ((destOffset & 7) == 0 && (leftOffset & 7) == 0 && (rightOffset & 7) == 0) // all offsets must be multiples of 8 for long-sized xor
            {
                Union destUnion = new Union { Bytes = dest }, leftUnion = new Union { Bytes = left }, rightBuffer = new Union { Bytes = right };
                int longDestOffset = destOffset >> 3, longLeftOffset = leftOffset >> 3, longRightOffset = rightOffset >> 3, longCount = byteCount >> 3;
                for (; i < longCount; ++i) destUnion.Longs[longDestOffset + i] = leftUnion.Longs[longLeftOffset + i] ^ rightBuffer.Longs[longRightOffset + i];
                i = longCount << 3;
            }
            for (; i < byteCount; ++i) dest[destOffset + i] = (byte)(left[leftOffset + i] ^ right[rightOffset + i]);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="dest"></param>
        /// <param name="destOffset"></param>
        /// <param name="left"></param>
        /// <param name="leftOffset"></param>
        /// <param name="byteCount"></param>
        public static void Xor(byte[] dest, int destOffset, byte[] left, int leftOffset, int byteCount)
        {
            int i = 0;
            if ((destOffset & 7) == 0 && (leftOffset & 7) == 0) // all offsets must be multiples of 8 for long-sized xor
            {
                Union destUnion = new Union { Bytes = dest }, leftUnion = new Union { Bytes = left };
                int longDestOffset = destOffset >> 3, longLeftOffset = leftOffset >> 3, longCount = byteCount >> 3;
                for (; i < longCount; ++i) destUnion.Longs[longDestOffset + i] ^= leftUnion.Longs[longLeftOffset + i];
                i = longCount << 3;
            }
            for (; i < byteCount; ++i) dest[destOffset + i] ^= left[leftOffset + i];
        }
    }
}
