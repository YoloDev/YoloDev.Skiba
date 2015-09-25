using System;
using System.IO;

namespace YoloDev.Skiba.Impl
{
    public class MultiByteArrayStream : Stream
    {
        readonly byte[][] _data;
        readonly int _length;
        int _currentArray = 0;
        int _currentPosition = 0;
        int _totalPos = 0;

        public MultiByteArrayStream(params byte[][] data)
        {
            _data = data;
            int length = 0;
            for (int i = 0; i < data.Length; i++)
                length += data[i].Length;

            _length = length;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _length;

        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }

            set
            {
                throw new NotSupportedException();
            }
        }

        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int left = _length - _totalPos;
            count = Math.Min(count, left);
            int read = 0;

            while (count > 0)
            {
                var array = _data[_currentArray];
                left = array.Length - _currentPosition;

                var toRead = Math.Min(count, left);
                Buffer.BlockCopy(array, _currentPosition, buffer, offset, toRead);
                offset += toRead;
                read += toRead;
                _currentPosition += toRead;

                if (_currentPosition == array.Length)
                {
                    _currentPosition = 0;
                    _currentArray += 1;
                }
            }

            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}
