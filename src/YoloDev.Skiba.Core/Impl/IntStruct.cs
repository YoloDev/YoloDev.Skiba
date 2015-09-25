using System;
using System.Runtime.InteropServices;

namespace YoloDev.Skiba.Impl
{
    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct IntStruct
    {
        [FieldOffset(0)]
        public int IntValue;
        [FieldOffset(0)]
        public uint UintValue;

        [FieldOffset(0)]
        public byte B1;
        [FieldOffset(1)]
        public byte B2;
        [FieldOffset(2)]
        public byte B3;
        [FieldOffset(3)]
        public byte B4;

        /// <summary>
        /// To Big-Endian
        /// </summary>
        public void ToBEBytes(byte[] buffer, int offset = 0)
        {
            if (BitConverter.IsLittleEndian)
            {
                buffer[offset + 0] = B4;
                buffer[offset + 1] = B3;
                buffer[offset + 2] = B2;
                buffer[offset + 3] = B1;
            }
            else
            {
                buffer[offset + 0] = B1;
                buffer[offset + 1] = B2;
                buffer[offset + 2] = B3;
                buffer[offset + 3] = B4;
            }
        }
    }
}
