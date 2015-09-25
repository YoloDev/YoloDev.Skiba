using System.Security.Cryptography;

namespace YoloDev.Skiba.Hash
{
    public class HashFactory
    {
        public static SHA256 SHA256() =>
#if !DNXCORE50
            new SHA256Cng();
#else
            System.Security.Cryptography.SHA256.Create();
#endif

        public static SHA384 SHA384() =>
#if !DNXCORE50
            new SHA384Cng();
#else
            System.Security.Cryptography.SHA384.Create();
#endif

        public static SHA512 SHA512() =>
#if !DNXCORE50
            new SHA512Cng();
#else
            System.Security.Cryptography.SHA512.Create();
#endif
    }
}
