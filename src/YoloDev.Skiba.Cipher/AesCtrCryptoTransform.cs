using System;
using System.Security.Cryptography;
using System.Threading;

namespace YoloDev.Skiba.Cipher
{
    public class AesCtrCryptoTransform : ICryptoTransform
    {
        static readonly ThreadLocal<byte[]> _counterBuffer = new ThreadLocal<byte[]>(() => new byte[AesConstants.AES_BLOCK_SIZE]);

        readonly ICryptoTransform _cryptoTransform;
        Aes _aes;

        public bool CanReuseTransform { get { return false; } }
        public bool CanTransformMultipleBlocks { get { return true; } }
        public int InputBlockSize { get { return AesConstants.AES_BLOCK_SIZE; } }
        public int OutputBlockSize { get { return AesConstants.AES_BLOCK_SIZE; } }

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="key"></param>
        /// <param name="counterBufferSegment"></param>
        /// <param name="aesFactory"></param>
        /// <exception cref="ArgumentException">
        /// <paramref name="counterBufferSegment"/> needs to have the same length as <see cref="AesConstants.STR_AES_BLOCK_SIZE"/>.
        /// </exception>
        public AesCtrCryptoTransform(byte[] key, ArraySegment<byte> counterBufferSegment, Func<Aes> aesFactory = null)
        {
            if (counterBufferSegment.Count != AesConstants.AES_BLOCK_SIZE)
                throw new ArgumentException($"{nameof(counterBufferSegment)}.Count must be {AesConstants.STR_AES_BLOCK_SIZE}.", nameof(counterBufferSegment));

            _aes = aesFactory?.Invoke() ?? CipherFactory.Aes();
            _aes.Mode = CipherMode.ECB;
            _aes.Padding = PaddingMode.None;

            Buffer.BlockCopy(counterBufferSegment.Array, counterBufferSegment.Offset, _counterBuffer.Value, 0, AesConstants.AES_BLOCK_SIZE);
            _cryptoTransform = _aes.CreateEncryptor(rgbKey: key, rgbIV: null);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="inputBuffer"></param>
        /// <param name="inputOffset"></param>
        /// <param name="inputCount"></param>
        /// <param name="outputBuffer"></param>
        /// <param name="outputOffset"></param>
        /// <returns></returns>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            int partialBlockSize = inputCount % AesConstants.AES_BLOCK_SIZE;
            int fullBlockSize = inputCount - partialBlockSize;
            byte[] counterBuffer = _counterBuffer.Value; // looks dumb, but local-access is faster than field-access

            int i, j;

            for (i = outputOffset, /* reusing inputCount as iMax */ inputCount = outputOffset + fullBlockSize; i < inputCount; i += AesConstants.AES_BLOCK_SIZE)
            {
                Buffer.BlockCopy(counterBuffer, 0, outputBuffer, i, AesConstants.AES_BLOCK_SIZE);
                for (j = AesConstants.AES_BLOCK_SIZE - 1; j >= AesConstants.AES_BLOCK_SIZE - AesConstants.COUNTER_SIZE; --j)
                    if (++counterBuffer[j] != 0) break;
            }

            if (fullBlockSize > 0)
            {
                fullBlockSize = _cryptoTransform.TransformBlock(outputBuffer, outputOffset, fullBlockSize, outputBuffer, outputOffset);
                //for (i = 0; i < fullBlockSize; ++i) outputBuffer[outputOffset + i] ^= inputBuffer[inputOffset + i];
                Utils.Xor(outputBuffer, outputOffset, inputBuffer, inputOffset, fullBlockSize);
            }

            if (partialBlockSize > 0)
            {
                outputOffset += fullBlockSize;
                inputOffset += fullBlockSize;
                _cryptoTransform.TransformBlock(counterBuffer, 0, AesConstants.AES_BLOCK_SIZE, counterBuffer, 0);
                for (i = 0; i < partialBlockSize; ++i) outputBuffer[outputOffset + i] = (byte)(counterBuffer[i] ^ inputBuffer[inputOffset + i]);
            }
            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] outputBuffer = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
            Dispose();
            return outputBuffer;
        }

        public void Dispose()
        {
            if (_aes != null) // null aes acts as "isDisposed" flag
            {
                try
                {
                    _cryptoTransform.Dispose();
                    _aes.Dispose();
                }
                finally
                {
                    Array.Clear(_counterBuffer.Value, 0, AesConstants.AES_BLOCK_SIZE);
                    _aes = null;
                }
            }
        }
    }
}
