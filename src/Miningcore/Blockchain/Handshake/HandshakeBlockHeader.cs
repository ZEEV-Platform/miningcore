using Miningcore.Crypto.Hashing.Handshake.Blake2b;
using NBitcoin;
using NBitcoin.DataEncoders;
using System.IO;

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
        private uint256 hashMask;
        private uint nBits;
        private uint nNonce;
        private uint nTime;
        private int nVersion;
        private byte[] extraNonce = new byte[24];
        private byte[] paddingBytes = new byte[20];
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

        public uint256 HashMask
        {
            get => hashMask;
            set => hashMask = value;
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

        private byte[] maskHash(byte[] prevBlockHash)
        {
            var blake2bConfig = new Blake2BConfig();
            blake2bConfig.OutputSizeInBytes = 32;
            return Blake2B.ComputeHash(prevBlockHash.Concat(new byte[32]).ToArray(), blake2bConfig);
        }

        private byte[] subHash()
        {
            using(var ms = new MemoryStream())
            {
                var stream = new BitcoinStream(ms, true);

                stream.ReadWrite(ref extraNonce);
                stream.ReadWrite(ref hashReservedRoot);
                stream.ReadWrite(ref hashWitnessRoot);
                stream.ReadWrite(ref hashMerkleRoot);
                stream.ReadWrite(ref nVersion);

                //    stream.IsBigEndian = true;
                stream.ReadWrite(ref nBits);
                //    stream.IsBigEndian = false;

                //var reversedBitBytes = new byte[4];
                //this.bitsBytes.CopyTo(reversedBitBytes, 0);
                //Array.Reverse(reversedBitBytes);
                //stream.ReadWriteBytes(ref reversedBitBytes);

                var bytes = ms.GetBuffer();
                Array.Resize(ref bytes, (int) ms.Length);

                var blake2bConfig = new Blake2BConfig();
                blake2bConfig.OutputSizeInBytes = 32;
                return Blake2B.ComputeHash(bytes, blake2bConfig);
            }
        }

        private byte[] commitHash(byte[] prevBlockHash)
        {
            var blake2bConfig = new Blake2BConfig();
            blake2bConfig.OutputSizeInBytes = 32;
            return Blake2B.ComputeHash(subHash().Concat(maskHash(prevBlockHash)).ToArray(), blake2bConfig);
        }

        private byte[] padding(int size, byte[] prevBlock, byte[] treeRoot)
        {
            var pad = new byte[size];

            for(int i = 0; i < size; i++)
            {
                pad[i] = (byte) (prevBlock[i % 32] ^ treeRoot[i % 32]);
            }

            return pad;
        }

        public byte[] ToMiner()
        {
            using(var ms = new MemoryStream())
            {
                var stream = new BitcoinStream(ms, true);

                stream.ReadWrite(ref nNonce);

                var longTime = Convert.ToUInt64(nTime);
                timeBytes = BitConverter.GetBytes(longTime);
                ReadWriteBytes(stream, ref timeBytes);

                paddingBytes = padding(20, hashPrevBlock.ToBytes(), hashTreeRoot.ToBytes());
                ReadWriteBytes(stream, ref paddingBytes);

                stream.ReadWrite(ref hashPrevBlock);
                stream.ReadWrite(ref hashTreeRoot);

                hashCommitHash = new uint256(commitHash(hashPrevBlock.ToBytes()));
                stream.ReadWrite(ref hashCommitHash);

                ReadWriteBytes(stream, ref extraNonce);
                stream.ReadWrite(ref hashReservedRoot);
                stream.ReadWrite(ref hashWitnessRoot);
                stream.ReadWrite(ref hashMerkleRoot);
                stream.ReadWrite(ref nVersion);
                stream.ReadWrite(ref nBits);

                var bytes = ms.GetBuffer();
                Array.Resize(ref bytes, (int) ms.Length);
                return bytes;
            }
        }

        public void ReadWrite(BitcoinStream stream)
        {
            stream.ReadWrite(ref nNonce);

            if(stream.Serializing)
            {
                var longTime = Convert.ToUInt64(nTime);
                timeBytes = BitConverter.GetBytes(longTime);
                ReadWriteBytes(stream, ref timeBytes);

               // paddingBytes = padding(20, hashPrevBlock.ToBytes(), hashTreeRoot.ToBytes());
                //ReadWriteBytes(stream, ref paddingBytes);

                stream.ReadWrite(ref hashPrevBlock);
                stream.ReadWrite(ref hashTreeRoot);

              //  hashCommitHash = new uint256(commitHash(hashPrevBlock.ToBytes()));
              //  stream.ReadWrite(ref hashCommitHash);

                ReadWriteBytes(stream, ref extraNonce);
                stream.ReadWrite(ref hashReservedRoot);
                stream.ReadWrite(ref hashWitnessRoot);
                stream.ReadWrite(ref hashMerkleRoot);
                stream.ReadWrite(ref nVersion);
                stream.ReadWrite(ref nBits);

                stream.ReadWrite(ref hashMask);
            }
            else
            {
                ReadWriteBytes(stream, ref timeBytes);
                nTime = (uint) BitConverter.ToUInt64(timeBytes, 0);

               // ReadWriteBytes(stream, ref paddingBytes);
                stream.ReadWrite(ref hashPrevBlock);
                stream.ReadWrite(ref hashTreeRoot);
            //    stream.ReadWrite(ref hashCommitHash);

                ReadWriteBytes(stream, ref extraNonce);
                stream.ReadWrite(ref hashReservedRoot);
                stream.ReadWrite(ref hashWitnessRoot);
                stream.ReadWrite(ref hashMerkleRoot);
                stream.ReadWrite(ref nVersion);
                stream.ReadWrite(ref nBits);

                stream.ReadWrite(ref hashMask);
            }
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
            hashTreeRoot = 0;
            hashCommitHash = 0;
            hashWitnessRoot = 0;
            hashMask = 0;
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
