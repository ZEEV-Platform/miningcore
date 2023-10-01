using Miningcore.Contracts;
using Miningcore.Crypto.Hashing.Handshake.Blake2b;
using Miningcore.Crypto.Hashing.Handshake.SHA3;

namespace Miningcore.Crypto.Hashing.Handshake;

[Identifier("handshake")]
public unsafe class HandShake : IHashAlgorithm
{
    private readonly object hashLock;

    public HandShake()
    {
        this.hashLock = new object();
    }

    public void Digest(ReadOnlySpan<byte> input, out Span<byte> result, params object[] extra)
    {
        var buffer = input.ToArray();

            lock(this.hashLock)
            {
                //fromMiner(data) {
                //    const br = bio.read(data);

                //    // Preheader.
                //    this.nonce = br.readU32();
                //    this.time = br.readU64();

                //    const padding = br.readBytes(20);

                //    this.prevBlock = br.readHash();
                //    this.treeRoot = br.readHash();

                //    assert(padding.equals(this.padding(20)));

                //    // Note: mask _hash_.
                //    this._maskHash = br.readHash();

                //    // Subheader.
                //    this.extraNonce = br.readBytes(consensus.NONCE_SIZE);
                //    this.reservedRoot = br.readHash();
                //    this.witnessRoot = br.readHash();
                //    this.merkleRoot = br.readHash();
                //    this.version = br.readU32();
                //    this.bits = br.readU32();

                //    // Mask (unknown).
                //    this.mask = Buffer.alloc(32, 0x00);

                //    return this;
                //}

                //toPrehead() {
                //    const bw = bio.write(128);


                //    bw.writeU32(this.nonce);
                //    bw.writeU64(this.time);
                //    bw.writeBytes(this.padding(20));
                //    bw.writeHash(this.prevBlock);
                //    bw.writeHash(this.treeRoot);
                //    bw.writeHash(this.commitHash());

                //    // Exactly one blake2b block (128 bytes).
                //    assert(bw.offset === BLAKE2b.blockSize);

                //    return bw.render();
                //}
                var subHeader = buffer.Skip(128).Take(128).ToArray();
                var blake2bConfig = new Blake2BConfig();
                blake2bConfig.OutputSizeInBytes = 32;
                var subHeaderHash = Blake2B.ComputeHash(subHeader, blake2bConfig);

                var maskHash = buffer.Skip(96).Take(32).ToArray();
                var prevBlock = buffer.Skip(32).Take(32).ToArray();
                var commithash = Blake2B.ComputeHash(subHeaderHash.Concat(maskHash).ToArray(), blake2bConfig);

                var data = buffer.Take(96).Concat(commithash).ToArray();

                //padding(size) {
                //    assert((size >>> 0) === size);

                //    const pad = Buffer.alloc(size);

                //    for (let i = 0; i < size; i++)
                //        pad[i] = this.prevBlock[i % 32] ^ this.treeRoot[i % 32];

                //    return pad;
                //}

                var treeRoot = buffer.Skip(64).Take(32).ToArray();
                var pad8 = new byte[8];
                var pad32 = new byte[32];

                for(int i = 0; i < pad8.Length; i++)
                {
                    pad8[i] = (byte) (prevBlock[i % 32] ^ treeRoot[i % 32]);
                }

                for(int i = 0; i < pad32.Length; i++)
                {
                    pad32[i] = (byte) (prevBlock[i % 32] ^ treeRoot[i % 32]);
                }

                var left = Blake2B.ComputeHash(data);
                var right = Sha3.Sha3256().ComputeHash(data.Concat(pad8).ToArray());
                buffer = Blake2B.ComputeHash(left.Concat(pad32).Concat(right).ToArray(), blake2bConfig);

                result = buffer.Take(32).ToArray();
        }
    }

    public void Digest(ReadOnlySpan<byte> data, Span<byte> result, params object[] extra)
    {
        throw new NotImplementedException();
    }
}
