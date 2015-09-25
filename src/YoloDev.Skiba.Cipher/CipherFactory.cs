using System.Security.Cryptography;

namespace YoloDev.Skiba.Cipher
{
    public static class CipherFactory
    {
        public static Aes Aes() =>
#if !DNXCORE50
            new AesCryptoServiceProvider();
#else
            System.Security.Cryptography.Aes.Create();
#endif
    }
}
