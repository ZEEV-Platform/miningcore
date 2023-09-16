using NBitcoin;
using NBitcoin.DataEncoders;

namespace Miningcore.Blockchain.Handshake
{
    public class HandshakeBlockHeader : IBitcoinSerializable
    {
        public HandshakeBlockHeader(string hex)
            : this(Encoders.Hex.DecodeData(hex))
        {
        }

        public HandshakeBlockHeader(byte[] bytes)
        {
            ReadWrite(new BitcoinStream(bytes));
        }

        public HandshakeBlockHeader()
        {
            SetNull();
        }

        private uint256 hashMerkleRoot;
        private uint256 hashPrevBlock;
        private uint256 hashReservedRoot;
        private uint256 hashTreeRoot;
        private uint256 hashCommitHash;
        private uint256 hashWitnessRoot;
        private uint nBits;
        private uint nNonce;
        private uint nTime;
        private int nVersion;
        private byte[] extraNonce = new byte[24];
        private byte[] reservedBytes = new byte[20];
        private byte[] timeBytes = new byte[8];

        // header
        private const int CURRENT_VERSION = 1;

        public uint256 HashPrevBlock
        {
            get => hashPrevBlock;
            set => hashPrevBlock = value;
        }

        public Target Bits
        {
            get => nBits;
            set => nBits = value;
        }

        public int Version
        {
            get => nVersion;
            set => nVersion = value;
        }

        public uint Nonce
        {
            get => nNonce;
            set => nNonce = value;
        }

        public uint256 HashMerkleRoot
        {
            get => hashMerkleRoot;
            set => hashMerkleRoot = value;
        }

        public uint256 HashReservedRoot
        {
            get => hashReservedRoot;
            set => hashReservedRoot = value;
        }

        public uint256 HashTreeRoot
        {
            get => hashTreeRoot;
            set => hashTreeRoot = value;
        }

        public uint256 HashWitnessRoot
        {
            get => hashWitnessRoot;
            set => hashWitnessRoot = value;
        }

        public uint256 HashCommitHash
        {
            get => hashCommitHash;
            set => hashCommitHash = value;
        }

        public byte[] ExtraNonce
        {
            get { return extraNonce; }
            set { extraNonce = value; }
        }
        public bool IsNull => nBits == 0;

        public uint NTime
        {
            get => nTime;
            set => nTime = value;
        }

        public DateTimeOffset BlockTime
        {
            get => Utils.UnixTimeToDateTime(nTime);
            set => nTime = Utils.DateTimeToUnixTime(value);
        }

        #region IBitcoinSerializable Members

        public void ReadWrite(BitcoinStream stream)
        {
            stream.ReadWrite(ref nNonce);

            if(stream.Serializing)
            {
                var longTime = Convert.ToUInt64(nTime);
                timeBytes = BitConverter.GetBytes(longTime);
                ReadWriteBytes(stream, ref timeBytes);
            }
            else
            {
                ReadWriteBytes(stream, ref timeBytes);
                nTime = (uint) BitConverter.ToUInt64(timeBytes, 0);
            }

            ReadWriteBytes(stream, ref reservedBytes);
            stream.ReadWrite(ref hashPrevBlock);
            stream.ReadWrite(ref hashTreeRoot);
            stream.ReadWrite(ref hashCommitHash);
            ReadWriteBytes(stream, ref extraNonce);
            stream.ReadWrite(ref hashReservedRoot);
            stream.ReadWrite(ref hashWitnessRoot);
            stream.ReadWrite(ref hashMerkleRoot);
            stream.ReadWrite(ref nVersion);
            stream.ReadWrite(ref nBits);
        }

        #endregion

        public static HandshakeBlockHeader Parse(string hex)
        {
            return new(Encoders.Hex.DecodeData(hex));
        }

        internal void SetNull()
        {
            nVersion = CURRENT_VERSION;
            hashPrevBlock = 0;
            hashMerkleRoot = 0;
            hashReservedRoot = 0;
            nTime = 0;
            nBits = 0;
            nNonce = 0;
        }

        public void ReadWriteBytes(BitcoinStream stream, ref byte[] data, int offset = 0, int count = -1)
        {
            if(data == null)
                throw new ArgumentNullException(nameof(data));
            if(data.Length == 0)
                return;
            count = count == -1 ? data.Length : count;
            if(count == 0)
                return;
            ReadWriteBytes(stream, new Span<byte>(data, offset, count));
        }

        private void ReadWriteBytes(BitcoinStream stream, Span<byte> data)
        {
            if(stream.Serializing)
            {
                stream.Inner.Write(data);
                stream.Counter.AddWritten(data.Length);
            }
            else
            {
                var read = stream.Inner.ReadEx(data, stream.ReadCancellationToken);
                if(read == 0)
                    throw new EndOfStreamException("No more byte to read");
                stream.Counter.AddReaden(read);
            }
        }
    }
}
