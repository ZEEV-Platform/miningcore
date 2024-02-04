using Miningcore.Blockchain.Handshake;
using NBitcoin;
using NBitcoin.Altcoins;
using NBitcoin.DataEncoders;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Handshake;
using Miningcore.Extensions;

namespace Miningcore.Tests.Blockchain.HandShake
{
    public class HandShakeHeaderTests : TestBase
    {

        [Fact]
        public void HeaderSerializationTest()
        {
            //test of block new
             var headerHasher = new Miningcore.Crypto.Hashing.Handshake.HandShake();

            var headerHex2 = "04d36800ac92bf65000000002d130e68859e7122883c0122bb6164ff0cc208eb6c645f65fe51a9ca1cf5ca1a00000000000000000000000000000000000000000000000000000000000000002b5850a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004574e02c61b92f03eb333c579284904d3c615154d44860bf9e98f5820bbb70b30000000021c2001c0000000000000000000000000000000000000000000000000000000000000000";
            var header = Enumerable.Range(0, headerHex2.Length)
                 .Where(x => x % 2 == 0)
                 .Select(x => Convert.ToByte(headerHex2.Substring(x, 2), 16))
                 .ToArray();

            var headerBlock = new HandshakeBlockHeader(headerHex2);

            var serialize = headerBlock.ToBytes();
            var serializeHEX = Encoders.Hex.EncodeData(serialize);

            var headerHex208877 = "a6496be42fe1b065000000000000000000000005b4490d1678b73c066ed15b6cbe0e98f684612504ffa4f97e34059276d78aa47040ba328b408416b61c80ac212681e1948ac2622705af27f301fcaf2eb1143da20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffd4f0144d43f2d8bb5d0da049911c392ea51e8463c5e74c2ae51b70d3016f6ae037061a67848020dee27740f93d8f9a937a1912be6068e77adb85eb43cd43d000000005a6407190000000000000000000000000000000000000000000000000000000000000000";
            var header208877 = Enumerable.Range(0, headerHex208877.Length)
                 .Where(x => x % 2 == 0)
                 .Select(x => Convert.ToByte(headerHex208877.Substring(x, 2), 16))
                 .ToArray();

            var h208877 = new HandshakeBlockHeader(header208877);

            headerBlock.Version = headerBlock.Version; //does not affect
            headerBlock.HashReservedRoot = headerBlock.HashReservedRoot; //does not affect
            headerBlock.HashMask = headerBlock.HashMask; //does not affect

            //headerBlock.Bits = new Target(h208877.Bits);
            //headerBlock.HashTreeRoot = h208877.HashTreeRoot;
            //headerBlock.HashMerkleRoot = h208877.HashMerkleRoot;
            //headerBlock.HashPrevBlock = h208877.HashPrevBlock;
            //headerBlock.HashWitnessRoot = h208877.HashWitnessRoot;
            //headerBlock.Nonce = h208877.Nonce;
            //headerBlock.BlockTime = h208877.BlockTime;

            var extra1 = "80000001";
            var extra2 = "324bc8bf";
            var extraNonce = (extra1 + extra2).HexToByteArray().Reverse().ToArray();
            Array.Resize(ref extraNonce, 24);

            headerBlock.ExtraNonce = extraNonce;

            var serializeBE = headerBlock.ToMiner();
            var serializeBEHEX = Encoders.Hex.EncodeData(serializeBE);

            Span<byte> headerHash = stackalloc byte[32];
            headerHasher.Digest(serializeBE, out headerHash);
            var headerValue = new uint256(headerHash);

            var isBlockCandidate = headerValue <= headerBlock.Bits.ToUInt256();

            Assert.True(isBlockCandidate);
        }

        [Fact]
        public void HeaderSerializationTest2()
        {
            //test of block
            //https://hnsnetwork.com/blocks/208877
            var headerHasher = new Miningcore.Crypto.Hashing.Handshake.HandShake();

            var headerHex2 = "a6496be42fe1b065000000000000000000000005b4490d1678b73c066ed15b6cbe0e98f684612504ffa4f97e34059276d78aa47040ba328b408416b61c80ac212681e1948ac2622705af27f301fcaf2eb1143da20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffd4f0144d43f2d8bb5d0da049911c392ea51e8463c5e74c2ae51b70d3016f6ae037061a67848020dee27740f93d8f9a937a1912be6068e77adb85eb43cd43d000000005a6407190000000000000000000000000000000000000000000000000000000000000000";
            var header = Enumerable.Range(0, headerHex2.Length)
                 .Where(x => x % 2 == 0)
                 .Select(x => Convert.ToByte(headerHex2.Substring(x, 2), 16))
                 .ToArray();

            var headerBlock = new HandshakeBlockHeader(headerHex2);

            var serialize = headerBlock.ToBytes();
            var serializeHEX = Encoders.Hex.EncodeData(serialize);

            headerBlock.Bits = new Target(headerBlock.Bits);
            headerBlock.HashMask = headerBlock.HashMask;
            headerBlock.HashTreeRoot = headerBlock.HashTreeRoot;
            headerBlock.HashMerkleRoot = headerBlock.HashMerkleRoot;
            headerBlock.HashPrevBlock = headerBlock.HashPrevBlock;
            headerBlock.HashReservedRoot = headerBlock.HashReservedRoot;
            headerBlock.HashWitnessRoot = headerBlock.HashWitnessRoot;
            headerBlock.Version = headerBlock.Version;
            headerBlock.Nonce = headerBlock.Nonce;
            headerBlock.BlockTime = headerBlock.BlockTime;
            headerBlock.ExtraNonce = headerBlock.ExtraNonce;

            var serializeBE = headerBlock.ToMiner();
            var serializeBEHEX = Encoders.Hex.EncodeData(serializeBE);

            Span<byte> headerHash = stackalloc byte[32];
            headerHasher.Digest(serializeBE, out headerHash);
            var headerValue = new uint256(headerHash);

            Assert.Equal("0000000000000002ea65d0779d3817a6246bcb17649341cb17f4e6ce9c9905f2", headerValue.ToString());

            var blockTargetValue = new Target(0x1907645a);
            var isBlockCandidate = headerValue <= blockTargetValue.ToUInt256();

            Assert.True(isBlockCandidate);
        }
    }
}
