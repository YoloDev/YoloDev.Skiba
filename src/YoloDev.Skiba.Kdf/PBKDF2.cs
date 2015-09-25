using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using YoloDev.Skiba.Impl;

namespace YoloDev.Skiba.Kdf
{
    public class PBKDF2 : DeriveBytes
    {
        /// <summary>
		/// Default iteration count.
		/// </summary>
		public const int DefaultIterations = 10000;

        static readonly CryptoRandom rng = new CryptoRandom();

        int _blockSize, _endIndex, _startIndex;
        uint _block, _iterations;
        byte[] _buffer, _salt;
        HMAC _hmac;
        byte[] _inputBuffer = new byte[4];

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="hmacFactory">HMAC factory.</param>
        /// <param name="password">Password.</param>
        /// <param name="saltSize">Salt size.</param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="saltSize"/> is less than zero.
        /// </exception>
        public PBKDF2(Func<HMAC> hmacFactory, string password, int saltSize)
            : this(hmacFactory, password, saltSize, DefaultIterations)
        {
        }

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="hmacFactory">HMAC factory.</param>
        /// <param name="password">Password.</param>
        /// <param name="salt">Salt.</param>
        public PBKDF2(Func<HMAC> hmacFactory, string password, byte[] salt)
            : this(hmacFactory, password, salt, DefaultIterations)
        {
        }

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="hmacFactory">HMAC factory.</param>
        /// <param name="password">Password.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="iterations">Number of itterations.</param>
        public PBKDF2(Func<HMAC> hmacFactory, string password, byte[] salt, int iterations)
            : this(hmacFactory, password.ToBytes(), salt, iterations)
        {
        }

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="hmacFactory">HMAC factory.</param>
        /// <param name="password">Password.</param>
        /// <param name="saltSize">Salt size.</param>
        /// <param name="iterations">Number of itterations.</param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="saltSize"/> is less than zero.
        /// </exception>
        public PBKDF2(Func<HMAC> hmacFactory, string password, int saltSize, int iterations)
            : this(hmacFactory, password.ToBytes(), GenerateSalt(saltSize), iterations)
        {
        }

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="hmacFactory">HMAC factory.</param>
        /// <param name="password">Password.</param>
        /// <param name="salt">Salt size.</param>
        /// <param name="iterations">Number of itterations.</param>
        public PBKDF2(Func<HMAC> hmacFactory, byte[] password, byte[] salt, int iterations)
        {
            Salt = salt;
            IterationCount = iterations;
            _hmac = hmacFactory();
            _hmac.Key = password;
            _blockSize = _hmac.HashSize / 8;
            Reset();
        }

        static byte[] GenerateSalt(int saltSize)
        {
            if (saltSize < 0)
                throw new ArgumentOutOfRangeException("saltSize");

            byte[] data = new byte[saltSize];
            rng.NextBytes(data);
            return data;
        }

        /// <summary>
		/// Releases the unmanaged resources used, and optionally releases the managed resources.
		/// </summary>
		/// <param name="disposing">true to release both managed and unmanaged resources; false to release only managed resources.</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                if (_hmac != null)
                {
                    _hmac.Dispose();
                }
                if (_buffer != null)
                {
                    Array.Clear(_buffer, 0, _buffer.Length);
                }
                if (_salt != null)
                {
                    Array.Clear(_salt, 0, _salt.Length);
                }
            }
        }

        byte[] Func()
        {
            new IntStruct { UintValue = _block }.ToBEBytes(_inputBuffer);
            byte[] hash = _hmac.ComputeHash(new MultiByteArrayStream(_salt, _inputBuffer));
            _hmac.Initialize();
            byte[] buffer3 = hash;
            for (int i = 2; i <= _iterations; i++)
            {
                hash = _hmac.ComputeHash(hash);
                for (int j = 0; j < _blockSize; j++)
                {
                    buffer3[j] ^= hash[j];
                }
            }
            _block++;
            return buffer3;
        }

        /// <summary>
        /// Gets or sets the number of iterations for the operation.
        /// </summary>
        public int IterationCount
        {
            get
            {
                return (int)_iterations;
            }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(value));

                _iterations = (uint)value;
                Reset();
            }
        }

        /// <summary>
        /// Gets or sets the key salt value for the operation.
        /// </summary>
        public IList<byte> Salt
        {
            get
            {
                return ImmutableArray.Create(_salt);
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                if (value.Count < 8)
                    throw new ArgumentException("Salt is not at least 8 bytes.");

                var salt = new byte[value.Count];
                value.CopyTo(salt, 0);
                _salt = salt;
                Reset();
            }
        }

        /// <summary>
        /// Returns pseudo-random bytes.
        /// </summary>
        /// <param name="cb">The number of pseudo-random bytes to generate.</param>
        /// <returns></returns>
        public override byte[] GetBytes(int cb)
        {
            if (cb <= 0)
                throw new ArgumentOutOfRangeException(nameof(cb), "Positive number required");

            byte[] dst = new byte[cb];
            int dstOffsetBytes = 0;
            int byteCount = _endIndex - _startIndex;
            if (byteCount > 0)
            {
                if (cb < byteCount)
                {
                    Buffer.BlockCopy(_buffer, _startIndex, dst, 0, cb);
                    _startIndex += cb;
                    return dst;
                }
                Buffer.BlockCopy(_buffer, _startIndex, dst, 0, byteCount);
                _startIndex = _endIndex = 0;
                dstOffsetBytes += byteCount;
            }

            while (dstOffsetBytes < cb)
            {
                byte[] src = Func();
                int num3 = cb - dstOffsetBytes;
                if (num3 > _blockSize)
                {
                    Buffer.BlockCopy(src, 0, dst, dstOffsetBytes, _blockSize);
                    dstOffsetBytes += _blockSize;
                }
                else
                {
                    Buffer.BlockCopy(src, 0, dst, dstOffsetBytes, num3);
                    dstOffsetBytes += num3;
                    Buffer.BlockCopy(src, num3, _buffer, _startIndex, _blockSize - num3);
                    _endIndex += _blockSize - num3;
                    return dst;
                }
            }

            return dst;
        }

        /// <summary>
		/// Resets the state.
		/// </summary>
		/// <remarks>
		/// This method is automatically called if the salt or iteration count is modified.
		/// </remarks>
		public override void Reset()
        {
            if (_buffer != null)
                Array.Clear(_buffer, 0, _buffer.Length);

            _buffer = new byte[_blockSize];
            _block = 1;
            _startIndex = _endIndex = 0;
        }
    }
}
