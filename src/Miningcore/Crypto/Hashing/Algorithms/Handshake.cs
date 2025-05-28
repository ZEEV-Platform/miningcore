using Miningcore.Contracts;
using Blockcore.NBitcoin;
using System.Text;
using Blockcore.NBitcoin.Crypto;

namespace Miningcore.Crypto.Hashing.Algorithms;

[Identifier("handshake")]
public unsafe class Handshake : IHashAlgorithm
{
    private readonly object hashLock;

    public Handshake()
    {
        hashLock = new object();
    }

    public void Digest(ReadOnlySpan<byte> data, Span<byte> result, params object[] extra)
    {
        throw new NotImplementedException();
    }

    public void Digest(ReadOnlySpan<byte> input, out Span<byte> result, params object[] extra)
    {
        var buffer = input.ToArray();

        lock(hashLock)
        {
            var prevBlock = buffer.Skip(32).Take(32).ToArray();
            var data = buffer.Take(128).ToArray();
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

            var left = Blake2B.Blake2B512().ComputeHash(data);
            var right = Sha3.Sha3256().ComputeHash(data.Concat(pad8).ToArray());
            buffer = Blake2B.Blake2B256().ComputeHash(left.Concat(pad32).Concat(right).ToArray());
            result = buffer.Take(32).Reverse().ToArray();
        }
    }
}
