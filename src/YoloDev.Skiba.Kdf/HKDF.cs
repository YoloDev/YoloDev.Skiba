using System;
using System.Security.Cryptography;

namespace YoloDev.Skiba.Kdf
{
    public class HKDF : DeriveBytes
    {
        static readonly byte[] emptyArray20 = new byte[20]; // for SHA-1
        static readonly byte[] emptyArray32 = new byte[32]; // for SHA-256
        static readonly byte[] emptyArray48 = new byte[48]; // for SHA-384
        static readonly byte[] emptyArray64 = new byte[64]; // for SHA-512

        readonly HMAC _hmac;
        int _hashLength;
        byte[] _context;
        byte _counter;
        byte[] _k;
        int _kUnused;

        public HKDF(Func<HMAC> hmacFactory, byte[] ikm, byte[] salt = null, byte[] context = null)
        {
            _hmac = hmacFactory();
            _hashLength = _hmac.HashSize / 8;

            // a malicious implementation of HMAC could conceivably mess up the shared static empty byte arrays, which are still writeable...
            _hmac.Key = salt ?? (_hashLength == 64 ? emptyArray64 : _hashLength == 48 ? emptyArray48 : _hashLength == 32 ? emptyArray32 : _hashLength == 20 ? emptyArray20 : new byte[_hashLength]);
            _hmac.Key = _hmac.ComputeHash(ikm); // re-keying hmac with PRK
            _context = context;

            Reset();
        }

        public override void Reset()
        {
            _k = ZeroLengthArray<byte>.Value;
            _kUnused = 0;
            _counter = 0;
        }

        protected override void Dispose(bool disposing)
        {
            if (_hmac != null)
                _hmac.Dispose();
        }

        public override byte[] GetBytes(int countBytes)
        {
            var okm = new byte[countBytes];
            if (_kUnused > 0)
            {
                var min = Math.Min(_kUnused, countBytes);
                Buffer.BlockCopy(_k, _hashLength - _kUnused, okm, 0, min);
                countBytes -= min;
                _kUnused -= min;
            }
            if (countBytes == 0) return okm;

            int n = countBytes / _hashLength + 1;
            int contextLength = _context != null ? _context.Length : 0;
            byte[] hmac_msg = new byte[_hashLength + contextLength + 1];

            for (var i = 1; i <= n; ++i)
            {
                Buffer.BlockCopy(_k, 0, hmac_msg, 0, _k.Length);
                if (contextLength > 0)
                    Buffer.BlockCopy(_context, 0, hmac_msg, _k.Length, contextLength);

                hmac_msg[_k.Length + contextLength] = checked(++_counter);

                _k = _hmac.ComputeHash(hmac_msg, 0, _k.Length + contextLength + 1);
                Buffer.BlockCopy(_k, 0, okm, okm.Length - countBytes, i < n ? _hashLength : countBytes);
                countBytes -= _hashLength;
            }
            _kUnused = -countBytes;
            return okm;
        }
    }
}
