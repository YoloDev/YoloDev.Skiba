using System;
using System.Security.Cryptography;

namespace YoloDev.Skiba
{
    /* Original version by Stephen Toub and Shawn Farkas.
	 * http://msdn.microsoft.com/en-us/magazine/cc163367.aspx
	 * Buffered concept from here: https://gist.github.com/1017834
	 */
    /// <summary>
    /// Represents a *thread-safe*, cryptographically-strong, pseudo-random number generator (based on RNGCryptoServiceProvider).
    /// 2-4 times slower than System.Random (would've been 150 times slower without buffering).
    /// </summary>
    public class CryptoRandom : Random
    {
        static RandomNumberGenerator _rng =
#if !DNXCORE50
            new RNGCryptoServiceProvider();
#else
            RandomNumberGenerator.Create(); // in DNXCORE50, the RNGCryptoServiceProvider is for some reason internal, though RandomNumberGenerator.Create() returns a new instance of it.
#endif
        const int BUFFER_SIZE = 1024 * 4; // 4k buffer seems to work best (empirical experimentation)
        const int BUFFERED_THRESHOLD = 100; // non-buffered approach seems faster beyond this point (empirical experimentation)

        readonly object lockObj = new object();
        byte[] _buffer = new byte[BUFFER_SIZE];
        int _bufferPosition = BUFFER_SIZE;

#region NextLong
        /// <summary>
        /// Returns a nonnegative random number.
        /// </summary>
        /// <returns>
        /// A 64-bit signed integer greater than or equal to zero and less than <see cref="long.MaxValue"/>.
        /// </returns>
        public long NextLong()
        {
            // Mask away the sign bit so that we always return nonnegative integers
            return (long)GetRandomULong() & 0x7FFFFFFFFFFFFFFF;
        }

        /// <summary>
        /// Returns a nonnegative random number less than the specified maximum.
        /// </summary>
        /// <param name="maxValue">The exclusive upper bound of the random number to be generated. <paramref name="maxValue"/> must be greater than or equal to zero.</param>
        /// <returns>
        /// A 64-bit signed integer greater than or equal to zero, and less than <paramref name="maxValue"/>; that is, the range of return values ordinarily
        /// includes zero but not <paramref name="maxValue"/>. However, if <paramref name="maxValue"/> equals zero, <paramref name="maxValue"/> is returned.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="maxValue"/> is less than zero.
        /// </exception>
        public long NextLong(long maxValue)
        {
            if (maxValue < 0)
                throw new ArgumentOutOfRangeException("maxValue");

            return NextLong(0, maxValue);
        }

        /// <summary>
        /// Returns a random number within a specified range.
        /// </summary>
        /// <param name="minValue">The inclusive lower bound of the random number returned.</param>
        /// <param name="maxValue">The exclusive upper bound of the random number returned. <paramref name="maxValue"/> must be greater than or equal to <paramref name="minValue"/>.</param>
        /// <returns>
        /// A 64-bit signed integer greater than or equal to <paramref name="minValue"/> and less than <paramref name="maxValue"/>; that is, the range of return values includes
        /// <paramref name="minValue"/> but not <paramref name="maxValue"/>. If <paramref name="minValue"/> equals <paramref name="maxValue"/>, <paramref name="minValue"/> is returned.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="minValue"/> is greater than <paramref name="maxValue"/>.
        /// </exception>
        public long NextLong(long minValue, long maxValue)
        {
            if (minValue == maxValue)
                return minValue;

            if (minValue > maxValue)
                throw new ArgumentOutOfRangeException("minValue");

            ulong diff = decimal.ToUInt64((decimal)maxValue - minValue);
            ulong upperBound = ulong.MaxValue / diff * diff - 1;

            ulong ul;
            do
            {
                ul = GetRandomULong();
            } while (ul > upperBound);
            return decimal.ToInt64((decimal)minValue + ul % diff);
        }
#endregion

#region Next
        /// <summary>
        /// Returns a nonnegative random number.
        /// </summary>
        /// <returns>
        /// A 32-bit signed integer greater than or equal to zero and less than <see cref="int.MaxValue"/>.
        /// </returns>
        public override int Next()
        {
            // Mask away the sign bit so that we always return nonnegative integers
            return (int)GetRandomUInt() & 0x7FFFFFFF;
        }

        /// <summary>
        /// Returns a nonnegative random number less than the specified maximum.
        /// </summary>
        /// <param name="maxValue">The exclusive upper bound of the random number to be generated. <paramref name="maxValue"/> must be greater than or equal to zero.</param>
        /// <returns>
        /// A 32-bit signed integer greater than or equal to zero, and less than <paramref name="maxValue"/>; that is, the range of return values ordinarily includes zero
        /// but not <paramref name="maxValue"/>. However, if <paramref name="maxValue"/> equals zero, <paramref name="maxValue"/> is returned.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="maxValue"/> is less than zero.
        /// </exception>
        public override int Next(int maxValue)
        {
            if (maxValue < 0)
                throw new ArgumentOutOfRangeException("maxValue");

            return Next(0, maxValue);
        }

        /// <summary>
        /// Returns a random number within a specified range.
        /// </summary>
        /// <param name="minValue">The inclusive lower bound of the random number returned.</param>
        /// <param name="maxValue">The exclusive upper bound of the random number returned. <paramref name="maxValue"/> must be greater than or equal to <paramref name="minValue"/>.</param>
        /// <returns>
        /// A 32-bit signed integer greater than or equal to <paramref name="minValue"/> and less than <paramref name="maxValue"/>;
        /// that is, the range of return values includes <paramref name="minValue"/> but not <paramref name="maxValue"/>. If <paramref name="minValue"/>
        /// equals <paramref name="maxValue"/>, <paramref name="minValue"/> is returned.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="minValue"/> is greater than <paramref name="maxValue"/>.
        /// </exception>
        public override int Next(int minValue, int maxValue)
        {
            if (minValue == maxValue)
                return minValue;

            if (minValue > maxValue)
                throw new ArgumentOutOfRangeException("minValue");

            long diff = (long)maxValue - minValue;
            long upperBound = uint.MaxValue / diff * diff - 1;

            uint ui;
            do
            {
                ui = GetRandomUInt();
            } while (ui > upperBound);
            return (int)(minValue + (ui % diff));
        }
#endregion

        /// <summary>
        /// Returns a random number between 0.0 and 1.0.
        /// </summary>
        /// <returns>
        /// A double-precision floating point number greater than or equal to 0.0, and less than 1.0.
        /// </returns>
        public override double NextDouble()
        {
            const double max = 1.0 + uint.MaxValue;
            return GetRandomUInt() / max;
        }

        /// <summary>
        /// Fills the elements of a specified array of bytes with random numbers.
        /// </summary>
        /// <param name="buffer">An array of bytes to contain random numbers.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="buffer"/> is null.
        /// </exception>
        public override void NextBytes(byte[] buffer)
        {
            var bufferLength = buffer.Length;
            if (bufferLength > BUFFERED_THRESHOLD)
            {
                _rng.GetBytes(buffer);
                return;
            }

            lock (lockObj)
            {
                if ((BUFFER_SIZE - _bufferPosition) < bufferLength)
                {
                    _rng.GetBytes(_buffer);
                    _bufferPosition = 0;
                }

                // Due to end goal being xplat, I'm not comfortable using reflection
                // to get at a InternalBlockCopy that (as far as I can tell) simply
                // skips some argument tests.
                Buffer.BlockCopy(_buffer, _bufferPosition, buffer, 0, bufferLength);
                _bufferPosition += bufferLength;
            }
        }

        /// <summary>
        /// Returns a new count-sized byte array filled with random bytes.
        /// </summary>
        /// <param name="count">Array length.</param>
        /// <returns>Random byte array.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="count"/> is less than zero.
        /// </exception>
        public byte[] NextBytes(int count)
        {
            if (count < 0)
                throw new ArgumentOutOfRangeException("count", "count must be non-negative.");

            byte[] bytes = new byte[count];
            NextBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// Get one random unsigned 32bit integer in a thread safe manner.
        /// </summary>
        /// <returns></returns>
        uint GetRandomUInt()
        {
            uint rand;
            lock (lockObj)
            {
                if ((BUFFER_SIZE - _bufferPosition) < sizeof(uint))
                {
                    _rng.GetBytes(_buffer);
                    _bufferPosition = 0;
                }

                rand = BitConverter.ToUInt32(_buffer, _bufferPosition);
                _bufferPosition += sizeof(uint);
            }
            return rand;
        }

        /// <summary>
		/// Gets one random unsigned 64bit integer in a thread safe manner.
		/// </summary>
        ulong GetRandomULong()
        {
            ulong rand;
            lock (lockObj)
            {
                if ((BUFFER_SIZE - _bufferPosition) < sizeof(ulong))
                {
                    _rng.GetBytes(_buffer);
                    _bufferPosition = 0;
                }

                rand = BitConverter.ToUInt64(_buffer, _bufferPosition);
                _bufferPosition += sizeof(ulong);
            }
            return rand;
        }
    }
}
