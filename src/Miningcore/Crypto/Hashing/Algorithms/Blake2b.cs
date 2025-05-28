using Blockcore.NBitcoin.Crypto;

namespace Miningcore.Crypto.Hashing.Algorithms;

[Identifier("blake2b")]
public unsafe class Blake2b : IHashAlgorithm
{
    private readonly object hashLock;
    public Blake2b()
    {
        this.hashLock = new object();
    }

    public void Digest(ReadOnlySpan<byte> data, out byte[] result, params object[] extra)
    {    
        var buffer = data.ToArray();

        lock(this.hashLock)
        {
            result = Blake2B.Blake2B256().ComputeHash(buffer);
        }
    }

    public void Digest(ReadOnlySpan<byte> data, Span<byte> result, params object[] extra)
    {
        throw new NotImplementedException();
    }
}
