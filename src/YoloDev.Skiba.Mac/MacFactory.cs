using System.Security.Cryptography;

namespace YoloDev.Mac
{
    public static class MacFactory
    {
        public static HMAC HMACSHA1() => new HMACSHA1();
        public static HMAC HMACSHA256() => new HMACSHA256();
        public static HMAC HMACSHA384() => new HMACSHA384();
        public static HMAC HMACSHA512() => new HMACSHA512();
    }
}
