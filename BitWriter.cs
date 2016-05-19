using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RtspNmosRelay
{
    //-----------------------------------------------------------------------------
    public class BitWriter
    //-----------------------------------------------------------------------------
    {
        protected byte [] m_buffer;
        protected int m_bytepos;
        protected int m_bitpos;

        //----------------------------------------------------------------
        public BitWriter(byte [] buf)
        //----------------------------------------------------------------
        {
            m_buffer = buf;
            m_bytepos = 0;
            m_bitpos = 0;
        }

        //----------------------------------------------------------------
        public void Put_Bits(uint val, int n)
        //----------------------------------------------------------------
        {
            if (n == 0)
                return;

            int bits_left = 8 - m_bitpos;

            if (n < bits_left)
            {
                val <<= (bits_left - n);
                m_buffer[m_bytepos] |= (byte)val;
                m_bitpos += n;
                return;
            }

            Int64 bigval = ((Int64)(m_buffer[m_bytepos]) << (n - bits_left)) | val;

            int nn = n + m_bitpos;

            while (nn >= 8)
            {
                Write_Byte((byte)(bigval >> (nn - 8)));
                nn -= 8;
            }

            m_bitpos += n;
            m_bitpos &= 7;

            if (nn != 0)
            {
                m_buffer[m_bytepos] = (byte)(bigval << (8 - m_bitpos));
            }
        }

        //----------------------------------------------------------------
        protected virtual void Write_Byte(byte val)
        //----------------------------------------------------------------
        {
            m_buffer[m_bytepos++] = val;
        }

        //----------------------------------------------------------------
        public void Put_Bits32_Aligned(uint val)
        //----------------------------------------------------------------
        {
            Align();
            Write_Byte((byte)(val >> 24));
            Write_Byte((byte)(val >> 16));
            Write_Byte((byte)(val >>  8));
            Write_Byte((byte)(val >>  0));
        }

        //----------------------------------------------------------------
        public bool Put_Bool(bool val)
        //----------------------------------------------------------------
        {
        	Put_Bits(val ? 1u : 0u, 1);
            return val;
        }

        //----------------------------------------------------------------
        private int BitsToAlign()
        //----------------------------------------------------------------
        {
            return ((m_bitpos - 1) & 7) ^ 7;
        }

        //----------------------------------------------------------------
        public bool IsAligned()
        //----------------------------------------------------------------
        {
            return (m_bitpos & 7) == 0;
        }

        //----------------------------------------------------------------
        public void Align()
        //----------------------------------------------------------------
        {
            //if(m_pos&7) m_pos = (m_pos+7)&~7;
            //m_pos += BitsToAlign();
            Put_Bits(0, BitsToAlign());
        }

        //----------------------------------------------------------------
        public int BitPos
        //----------------------------------------------------------------
        {
            get
            {
                return (m_bytepos << 3) + m_bitpos;
            }
            set
            {
                if (value > m_buffer.Length * 8)
                    throw new IndexOutOfRangeException("BitPos is outside the bounds");

                m_bytepos = value >> 3;
                m_bitpos = value & 7;
            }
        }

        //----------------------------------------------------------------
        public int BytesInBuffer
        //----------------------------------------------------------------
        {
            get
            {
                return (BitPos + 7) >> 3;
            }
        }
    }

    //-----------------------------------------------------------------------------
    public class H264BitWriter : BitWriter
    //-----------------------------------------------------------------------------
    {
        //----------------------------------------------------------------
        public H264BitWriter(byte[] buf) : base(buf)
        //----------------------------------------------------------------
        {
        }

        //----------------------------------------------------------------
        protected override void Write_Byte(byte val)
        //----------------------------------------------------------------
        {
            if(val <= 1 && m_bytepos >= 2 && m_buffer[m_bytepos-1] == 0 && m_buffer[m_bytepos - 2] == 0)
                m_buffer[m_bytepos++] = 03;

            m_buffer[m_bytepos++] = val;
        }

        //----------------------------------------------------------------
        public void Put_StartCode(int len)
        //----------------------------------------------------------------
        {
            Align();

            for (int i = 0; i < len - 1; i++)
                base.Write_Byte(0);

            base.Write_Byte(1);
        }

        //-----------------------------------------------------------------------------
        public void Put_UE(uint val)
        //-----------------------------------------------------------------------------
        {
            if(val == 0)
            {
                Put_Bits(1, 1);
                return;
            }

            val += 1;
            int lsb_pos = __bsr(val);

            Put_Bits(val, lsb_pos * 2 + 1);
        }

        //-----------------------------------------------------------------------------
        public void Put_SE(int val)
        //----------------------------------------------------------------
        {
            if (val > 0)
                Put_UE((uint)(val*2-1));
            else
                Put_UE((uint)(-val*2));
        }


#if true
        private static int __bsr(uint v)
        {
            int r = 0;
            while ((v >>= 1) != 0)
            {
                r++;
            }
            return r;
        }
#else
        private uint LeadingZeros(uint x)
        {
            x |= (x >> 1);
            x |= (x >> 2);
            x |= (x >> 4);
            x |= (x >> 8);
            x |= (x >> 16);
            return (sizeof(int) * 8 - Ones(x));
        }
        private uint Ones(uint x)
        {
            x -= ((x >> 1) & 0x55555555);
            x = (((x >> 2) & 0x33333333) + (x & 0x33333333));
            x = (((x >> 4) + x) & 0x0f0f0f0f);
            x += (x >> 8);
            x += (x >> 16);
            return (x & 0x0000003f);
        }
#endif
    }
}
