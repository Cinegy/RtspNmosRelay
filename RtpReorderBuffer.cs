using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace RtspNmosRelay
{
    class RtpReorderBuffer
    {
        private static int _inputOrderBufferSize;
        private static RtpPacket[] _inputRtpPacketOrderBuffer;
        private static int _bufferIdx = -1;
        private static int _lastPushedRtpSequence = -1;
        private static readonly object BufferLock = new object();
        private static int _outOfSequenceCounter = 0;
        private static ushort _lastReturnedRtpPacketSeq = 0;

        public RtpReorderBuffer()
        {
            _inputOrderBufferSize = 32;
            _inputRtpPacketOrderBuffer = new RtpPacket[_inputOrderBufferSize];
        }

        public RtpReorderBuffer(int bufferSize)
        {
            _inputOrderBufferSize = bufferSize;
            _inputRtpPacketOrderBuffer = new RtpPacket[_inputOrderBufferSize];
        }

        public ushort LastReturnedRtpSequenceNumber => _lastReturnedRtpPacketSeq;
        
        public void PushNewRtpPacket(RtpPacket packet)
        {
            if (packet?.Version != 2) return;

            lock (BufferLock)
            {
                try
                {
                    var seqInstantBufferNum = (packet.SequenceNumber + (_inputOrderBufferSize / 2)) % _inputOrderBufferSize;

                    if (_lastPushedRtpSequence < 0 || _outOfSequenceCounter > 8)
                    {
                        PrintToConsole("Resetting receiver buffer");
                        _inputRtpPacketOrderBuffer = new RtpPacket[_inputOrderBufferSize];
                        _bufferIdx = seqInstantBufferNum;
                        _outOfSequenceCounter = 0;
                    }

                    _lastPushedRtpSequence = packet.SequenceNumber;
                    
                    if (_bufferIdx != seqInstantBufferNum)
                    {
                        PrintToConsole(
                            $"Out-of-order packet - seq: {packet.SequenceNumber}, order delta: {seqInstantBufferNum - _bufferIdx}");
                        _outOfSequenceCounter++;
                    }
                    else
                    {
                        _outOfSequenceCounter = 0;
                    }

                    if (GetSequenceNumberDifference(packet.SequenceNumber, _lastPushedRtpSequence) > _inputOrderBufferSize / 2)
                    {
                        PrintToConsole("RTP packet large jump - resetting buffer");

                        _inputRtpPacketOrderBuffer = new RtpPacket[_inputOrderBufferSize];
                        _lastPushedRtpSequence = -1;
                        _bufferIdx = (packet.SequenceNumber + (_inputOrderBufferSize / 2)) % _inputOrderBufferSize;
                        _outOfSequenceCounter = 0;
                    }

                    var latestIndex = packet.SequenceNumber % _inputOrderBufferSize;

                    _inputRtpPacketOrderBuffer[latestIndex] = packet;
                }
                catch (Exception ex)
                {
                    PrintToConsole($@"Unhandled exception pushing RTP data to buffer: {ex.Message}");
                }
            }
        }

        public RtpPacket GetNextRtpPacket()
        {
            if (_bufferIdx < 0)
            {
                return null;
            }

            var bufferedPacket = _inputRtpPacketOrderBuffer[_bufferIdx++];

            if (_bufferIdx >= _inputOrderBufferSize) _bufferIdx = 0;

            if (bufferedPacket != null)
            {
                _lastReturnedRtpPacketSeq = bufferedPacket.SequenceNumber;
            }

            return bufferedPacket;
        }

        public static int GetSequenceNumberDifference(int firstSeq, int secondSeq)
        {
            var seqDiff = firstSeq - secondSeq;

            if ((firstSeq == ushort.MaxValue) & secondSeq == 0) return 1;

            if (seqDiff < 0)
            {
                seqDiff = firstSeq + (ushort.MaxValue + 1) - secondSeq;
            }

            if (seqDiff > ushort.MaxValue / 2)
            {
                seqDiff = secondSeq - firstSeq;
            }

            if (seqDiff < 0)
            {
                seqDiff = secondSeq + (ushort.MaxValue - 1) - firstSeq;
            }

            if (seqDiff > ushort.MaxValue / 2)
            {
                throw new Exception("Should be impossible");
            }

            return seqDiff;

        }
        
        private static void PrintToConsole(string message, bool verbose = false)
        {
            Console.WriteLine(message);
        }
    }
}
