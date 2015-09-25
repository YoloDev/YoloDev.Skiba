using System;

namespace YoloDev.Skiba
{
    public static class ArraySegmentExtensions
    {
        public static ArraySegment<T> AsArraySegment<T>(this T[] arr) { return new ArraySegment<T>(arr); }
        public static ArraySegment<T>? AsNullableArraySegment<T>(this T[] arr) { return new ArraySegment<T>?(new ArraySegment<T>(arr)); }
    }
}
