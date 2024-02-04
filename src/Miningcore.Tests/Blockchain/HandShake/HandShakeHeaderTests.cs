using Miningcore.Blockchain.Handshake;
using NBitcoin;
using NBitcoin.DataEncoders;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Miningcore.Tests.Blockchain.HandShake
{
    public class HandShakeHeaderTests : TestBase
    {

        [Fact]
        public void HeaderSerializationTest()
        {
            var headerHex2 = "09000000F0984B670000000000000000FFFF000000000000000000000000000000000000000000000000000000000000FFFF000000000000000000000000000000000000000000000000000064FCAF2EB1143DA20000000000000000000000000000000000000000FFFF000000000000000000000000000000000000000000000000000000000000FFFF000000000000000000000000000000000000000000000000000000000000FFFF0000000000000000000000000000000000000000000000000000E8030000FFFF001D00000000FFFF0000000000000000000000000000000000000000000000000000";
            var header = Enumerable.Range(0, headerHex2.Length)
                 .Where(x => x % 2 == 0)
                 .Select(x => Convert.ToByte(headerHex2.Substring(x, 2), 16))
                 .ToArray();

            var ss = new HandshakeBlockHeader(headerHex2);

            var serialize = ss.ToBytes();
            var serializeHEX = Encoders.Hex.EncodeData(serialize);

            ss.Bits = new Target(new uint256("00000000ffff0000000000000000000000000000000000000000000000000000"));
            ss.HashMask = new uint256("00000000ffff0000000000000000000000000000000000000000000000000000");
            ss.HashTreeRoot = new uint256("00000000ffff0000000000000000000000000000000000000000000000000000");
            ss.HashMerkleRoot = new uint256("00000000ffff0000000000000000000000000000000000000000000000000000");
            ss.HashPrevBlock = new uint256("00000000ffff0000000000000000000000000000000000000000000000000000");
            ss.HashReservedRoot = new uint256("00000000ffff0000000000000000000000000000000000000000000000000000");
            ss.HashWitnessRoot = new uint256("00000000ffff0000000000000000000000000000000000000000000000000000");
            ss.Version = 1000;
            ss.Nonce = 9;
            var unix = new DateTimeOffset(new DateTime(2024, 12, 1)).ToUnixTimeSeconds();
            ss.BlockTime = new DateTimeOffset(new DateTime(2024, 12, 1));
            ss.ExtraNonce[0] = 100;

            var serializeBE = ss.ToBytes();
            var serializeBEHEX = Encoders.Hex.EncodeData(serializeBE);
        }
    }
}
