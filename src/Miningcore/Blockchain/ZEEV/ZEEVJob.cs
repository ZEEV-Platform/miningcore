using System.Collections.Concurrent;
using System.Globalization;
using System.Numerics;
using System.Text;
using Autofac.Features.OwnedInstances;
using System.Text.RegularExpressions;
using Miningcore.Blockchain.ZEEV.Configuration;
using Miningcore.Blockchain.ZEEV.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Handshake;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NBitcoin.Altcoins;
using NBitcoin.DataEncoders;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Utilities;
using Parlot.Fluent;
using static Org.BouncyCastle.Bcpg.Attr.ImageAttrib;
using Contract = Miningcore.Contracts.Contract;
using Transaction = NBitcoin.Transaction;
using uint256 = NBitcoin.uint256;
using System;
using Org.BouncyCastle.Utilities.Encoders;
using Miningcore.Crypto.Hashing.Handshake.Blake2b;

namespace Miningcore.Blockchain.ZEEV;

public class ZEEVJob
{
    protected IHashAlgorithm blockHasher;
    protected IMasterClock clock;
    protected IHashAlgorithm coinbaseHasher;
    protected double shareMultiplier;
    protected int extraNoncePlaceHolderLength;
    protected IHashAlgorithm headerHasher;
    protected bool isPoS;
    protected string txComment;
    protected PayeeBlockTemplateExtra payeeParameters;

    protected Network network;
    protected IDestination poolAddressDestination;
    protected ZEEVCoinTemplate coin;
    private ZEEVCoinTemplate.ZEEVNetworkParams networkParams;
    protected readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);
    protected uint256 blockTargetValue;
    protected byte[] coinbaseFinal;
    protected string coinbaseFinalHex;
    protected byte[] coinbaseInitial;
    protected string coinbaseInitialHex;
    protected string[] merkleBranchesHex;
    protected byte[] merkleRootHash;
    protected string merkleRootHashHex;
    protected byte[] coinbaseHash;
    protected ZEEVMerkleTree mt;

    ///////////////////////////////////////////
    // GetJobParams related properties

    protected object[] jobParams;
    protected string previousBlockHashReversedHex;
    protected Money rewardToPool;
    protected Transaction txOut;

    // serialization constants
    protected byte[] scriptSigFinalBytes;

    protected static byte[] sha256Empty = new byte[32];
    protected uint txVersion = 1u; // transaction version (currently 1) - see https://en.ZEEV.it/wiki/Transaction

    protected static uint txInputCount = 1u;
    protected static uint txInPrevOutIndex = (uint) (Math.Pow(2, 32) - 1);
    protected static uint txInSequence;
    protected static uint txLockTime;

    protected virtual void BuildMerkleBranches()
    {
        var transactionHashes = BlockTemplate.Transactions
            .Select(tx => (tx.TxId ?? tx.Hash)
                .HexToByteArray()
                .ReverseInPlace())
        .ToArray();

        mt = new ZEEVMerkleTree(transactionHashes);

        merkleBranchesHex = mt.Steps
            .Select(x => x.ToHexString())
            .ToArray();

        var logger = LogUtil.GetPoolScopedLogger(typeof(ZEEVJob), "Zeev");

        var first = coinbaseHash;
        logger.Info(() => $"First {first.ToHexString()}");
        var blake2bConfig = new Blake2BConfig();
        blake2bConfig.OutputSizeInBytes = 32;

        foreach(var step in mt.Steps)
        {
            logger.Info(() => $"Step {step.ToHexString()}");
            first = Blake2B.ComputeHash(first.Concat(step).ToArray(), blake2bConfig);
            logger.Info(() => $"First {first.ToHexString()}");
        }

        var merkleRoot = mt.WithFirst(coinbaseHash).ToNewReverseArray();
        merkleRootHash = merkleRoot;
        merkleRootHashHex = merkleRoot.ToHexString();

        logger.Info(() => $"merkleRootHashHex {merkleRoot.ToHexString()}");
    }

    protected virtual void BuildCoinbase(bool withExtraNonce, long now)
    {
        // generate script parts
        var sigScriptInitial = GenerateScriptSigInitial(now);
        var sigScriptInitialBytes = sigScriptInitial.ToBytes();

        var sigScriptLength = (uint) (
            sigScriptInitial.Length +
            (withExtraNonce ? extraNoncePlaceHolderLength : 0) +
            scriptSigFinalBytes.Length);

        // output transaction
        txOut = CreateOutputTransaction();

        // build coinbase initial
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // version
            bs.ReadWrite(ref txVersion);

            // timestamp for POS coins
            if(isPoS)
            {
                var timestamp = BlockTemplate.CurTime;
                bs.ReadWrite(ref timestamp);
            }

            // serialize (simulated) input transaction
            bs.ReadWriteAsVarInt(ref txInputCount);
            bs.ReadWrite(ref sha256Empty);
            bs.ReadWrite(ref txInPrevOutIndex);

            // signature script initial part
            bs.ReadWriteAsVarInt(ref sigScriptLength);
            bs.ReadWrite(ref sigScriptInitialBytes);

            // done
            coinbaseInitial = stream.ToArray();
            coinbaseInitialHex = coinbaseInitial.Take(32).ToHexString();
        }

        // build coinbase final
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // signature script final part
            bs.ReadWrite(ref scriptSigFinalBytes);

            // tx in sequence
            bs.ReadWrite(ref txInSequence);

            // serialize output transaction
            var txOutBytes = SerializeOutputTransaction(txOut);
            bs.ReadWrite(ref txOutBytes);

            // misc
            bs.ReadWrite(ref txLockTime);

            // Extension point
            AppendCoinbaseFinal(bs);

            // done
            coinbaseFinal = stream.ToArray();
            coinbaseFinalHex = coinbaseFinal[^32..].ToHexString();

            //   coinbaseFinalHex = coinbaseFinal.ToHexString();
        }

        //we have to generate coinbase hash here
        coinbaseHash = new byte[32];
        coinbaseHasher.Digest(coinbaseInitial.Concat(coinbaseFinal).ToArray(), coinbaseHash);


    }

    protected virtual void AppendCoinbaseFinal(BitcoinStream bs)
    {
        if(!string.IsNullOrEmpty(txComment))
        {
            var data = Encoding.ASCII.GetBytes(txComment);
            bs.ReadWriteAsVarString(ref data);
        }

        if(coin.HasMasterNodes && !string.IsNullOrEmpty(masterNodeParameters.CoinbasePayload))
        {
            var data = masterNodeParameters.CoinbasePayload.HexToByteArray();
            bs.ReadWriteAsVarString(ref data);
        }
    }

    protected virtual byte[] SerializeOutputTransaction(Transaction tx)
    {
        var withDefaultWitnessCommitment = !string.IsNullOrEmpty(BlockTemplate.DefaultWitnessCommitment);

        var outputCount = (uint) tx.Outputs.Count;
        if(withDefaultWitnessCommitment)
            outputCount++;

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // write output count
            bs.ReadWriteAsVarInt(ref outputCount);

            long amount;
            byte[] raw;
            uint rawLength;

            // serialize witness (segwit)
            if(withDefaultWitnessCommitment)
            {
                amount = 0;
                raw = BlockTemplate.DefaultWitnessCommitment.HexToByteArray();
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(ref raw);
            }

            // serialize outputs
            foreach(var output in tx.Outputs)
            {
                amount = output.Value.Satoshi;
                var outScript = output.ScriptPubKey;
                raw = outScript.ToBytes(true);
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(ref raw);
            }

            return stream.ToArray();
        }
    }

    protected virtual Script GenerateScriptSigInitial(long now)
    {
        // script ops
        var ops = new List<Op>();

        // push block height
        ops.Add(Op.GetPushOp(BlockTemplate.Height));

        // optionally push aux-flags
        if(!coin.CoinbaseIgnoreAuxFlags && !string.IsNullOrEmpty(BlockTemplate.CoinbaseAux?.Flags))
            ops.Add(Op.GetPushOp(BlockTemplate.CoinbaseAux.Flags.HexToByteArray()));

        // push timestamp
        ops.Add(Op.GetPushOp(now));

        // push placeholder
        ops.Add(Op.GetPushOp(0));

        return new Script(ops);
    }

    protected virtual Transaction CreateOutputTransaction()
    {
        rewardToPool = new Money(BlockTemplate.CoinbaseValue, MoneyUnit.Satoshi);
        var tx = Transaction.Create(network);

        if(coin.HasPayee)
            rewardToPool = CreatePayeeOutput(tx, rewardToPool);

        if(coin.HasMasterNodes)
            rewardToPool = CreateMasternodeOutputs(tx, rewardToPool);

        if (coin.HasFounderFee)
            rewardToPool = CreateFounderOutputs(tx, rewardToPool);

        if (coin.HasMinerFund)
            rewardToPool = CreateMinerFundOutputs(tx, rewardToPool);

        // Remaining amount goes to pool
        tx.Outputs.Add(rewardToPool, poolAddressDestination);

        return tx;
    }

    protected virtual Money CreatePayeeOutput(Transaction tx, Money reward)
    {
        if(payeeParameters?.PayeeAmount != null && payeeParameters.PayeeAmount.Value > 0)
        {
            var payeeReward = new Money(payeeParameters.PayeeAmount.Value, MoneyUnit.Satoshi);
            reward -= payeeReward;

            tx.Outputs.Add(payeeReward, ZEEVUtils.AddressToDestination(payeeParameters.Payee, network));
        }

        return reward;
    }

    protected bool RegisterSubmit(string extraNonce1, string extraNonce2, string nTime, string nonce)
    {
        var key = new StringBuilder()
            .Append(extraNonce1)
            .Append(extraNonce2) // lowercase as we don't want to accept case-sensitive values as valid.
            .Append(nTime)
            .Append(nonce) // lowercase as we don't want to accept case-sensitive values as valid.
            .ToString();

        return submissions.TryAdd(key, true);
    }

    protected ZEEVBlockHeader SerializeHeader(Span<byte> coinbaseHash, uint nTime, uint nonce, byte[] extraNonce, uint? versionMask, uint? versionBits)
    {
        var headerHex2 = "a6496be42fe1b065000000000000000000000005b4490d1678b73c066ed15b6cbe0e98f684612504ffa4f97e34059276d78aa47040ba328b408416b61c80ac212681e1948ac2622705af27f301fcaf2eb1143da20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffd4f0144d43f2d8bb5d0da049911c392ea51e8463c5e74c2ae51b70d3016f6ae037061a67848020dee27740f93d8f9a937a1912be6068e77adb85eb43cd43d000000005a6407190000000000000000000000000000000000000000000000000000000000000000";
        var header = Enumerable.Range(0, headerHex2.Length)
             .Where(x => x % 2 == 0)
             .Select(x => Convert.ToByte(headerHex2.Substring(x, 2), 16))
             .ToArray();

        var test = new ZEEVBlockHeader(headerHex2);
        //var testBytes = test.ToBytes();
        //var testBytesMiner = test.ToMiner();
        //var testHex = Encoders.Hex.EncodeData(testBytes);
        //var testHexMiner = Encoders.Hex.EncodeData(testBytesMiner);

        // build merkle-root
       // var merkleRoot = mt.WithFirst(coinbaseHash.ToArray());

        //    return test;
        // Build version
        var version = BlockTemplate.Version;

        // Overt-ASIC boost
        if(versionMask.HasValue && versionBits.HasValue)
            version = (version & ~versionMask.Value) | (versionBits.Value & versionMask.Value);

        Array.Resize(ref extraNonce, 24);

        var testc = merkleRootHashHex;

#pragma warning disable 618
        var blockHeader = new ZEEVBlockHeader
#pragma warning restore 618
        {
            Version = unchecked((int) version),
            Bits = new Target(Encoders.Hex.DecodeData(BlockTemplate.Bits)),
            HashPrevBlock = uint256.Parse(BlockTemplate.PreviousBlockhash), //uint256.Parse("5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0"), 
            HashMerkleRoot = new uint256(merkleRootHash, false), // uint256.Parse(coinbaseInitialHex), // uint256.Parse("28b17095216d5e211ba1f61031416a51efca54eacb8c9059440c4671b0625bbe"), //new uint256(merkleRoot),
            BlockTime = DateTimeOffset.FromUnixTimeSeconds(nTime),
            Nonce = nonce,
            HashReservedRoot = uint256.Parse("0000000000000000000000000000000000000000000000000000000000000000"), //new uint256(),
            HashTreeRoot = uint256.Parse("0000000000000000000000000000000000000000000000000000000000000000"), //new uint256(),
            HashWitnessRoot = uint256.Parse(coinbaseFinalHex), // uint256.Parse("59919422c20530ece2b328adf63ec3f35a10e79375731687a81dfa7cd83a24e7"), //new uint256(),
            HashMask = uint256.Parse("0000000000000000000000000000000000000000000000000000000000000000"), //new uint256(),
            ExtraNonce = extraNonce
        };

        var testBytes = test.ToBytes();
        var blockBytes = blockHeader.ToBytes();

        var testBytesHex = Encoders.Hex.EncodeData(testBytes);
        var blockBytesHex = Encoders.Hex.EncodeData(blockBytes);

        //var testBytesMiner = test.ToMiner();
        //var testHex = Encoders.Hex.EncodeData(testBytes);
        //var testHexMiner = Encoders.Hex.EncodeData(testBytesMiner);

        return blockHeader;
    }

    public static BigInteger Div(BigInteger x, double y)
    {
        var yb = new BigInteger(y);

        if(Math.Abs(y) < double.Epsilon)
        {
            throw new ArgumentException("Division by zero is not allowed.");
        }

        BigInteger q = (BigInteger) (x / yb);

        if(x >= 0)
        {
            return q;
        }

        BigInteger r = x - (BigInteger) (q * yb);

        if(r < 0)
        {
            if(yb < 0)
                q += 1;
            else
                q -= 1;
        }

        return q;
    }

    static byte[] ToCompactByteArray(BigInteger num)
    {
        if(num.IsZero)
            return new byte[] { 0 };

        int exponent = num.ToByteArray().Length;
        int mantissa;

        if(exponent <= 3)
        {
            mantissa = (int) num;
            mantissa <<= 8 * (3 - exponent);
        }
        else
        {
            mantissa = (int) (num >> 8 * (exponent - 3));
        }

        if((mantissa & 0x800000) != 0)
        {
            mantissa >>= 8;
            exponent += 1;
        }

        int compact = (exponent << 24) | mantissa;

        if(num.Sign < 0)
            compact |= 0x800000;

        compact = (int) ((uint) compact);

        // Convert compact to a byte array
        List<byte> byteArray = new List<byte>();
        for(int i = 0; i < 4; i++)
        {
            byteArray.Insert(0, (byte) ((compact & (0xFF << (i * 8))) >> (i * 8)));
        }
        return byteArray.ToArray();
    }

    public static byte[] GetBitsFromDifficult(double difficulty)
    {
        BigInteger max = BigInteger.Parse("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", NumberStyles.HexNumber);

        var s = Div(max, difficulty);
        var cmpct = ToCompactByteArray(s);

        return cmpct;
    }

    protected virtual (Share Share, string BlockHex) ProcessShareInternal(
        StratumConnection worker, string extraNonce2, uint nTime, string nonceString, uint? versionBits)
    {
        uint nonce = uint.Parse(nonceString, NumberStyles.HexNumber);
        var nonceBytes = nonceString.HexToByteArray();

        var context = worker.ContextAs<ZEEVWorkerContext>();
        var extraNonce1 = context.ExtraNonce1;

        // build coinbase
        var coinbase = SerializeCoinbase(extraNonce1, extraNonce2);
        Span<byte> coinbaseHash = stackalloc byte[32];
        coinbaseHasher.Digest(coinbase, coinbaseHash);

        //----------------------------------------- hash block-header (extraNonce1 + extraNonce2).HexToByteArray()
        //nonceBytes.Concat((extraNonce2).HexToByteArray()).ToArray()
        // new byte[24]
        var header = SerializeHeader(coinbaseHash, nTime, nonce, (extraNonce1 + extraNonce2).HexToByteArray(), context.VersionRollingMask, versionBits);
        var headerBytesMiner = header.ToMiner();
        var headerBytesX = header.ToBytes();
        var headerBytesHex = Encoders.Hex.EncodeData(headerBytesX);
        var headerBytesMinerHex = Encoders.Hex.EncodeData(headerBytesMiner);
        Span<byte> headerHash = stackalloc byte[32];
        ((Handshake) headerHasher).Digest(headerBytesMiner, out headerHash, (ulong) nTime, BlockTemplate, coin, networkParams);
        var headerValueHex = Encoders.Hex.EncodeData(headerHash);
        var headerValue = new uint256(headerHash);
        var headerHashRev = new byte[32];
        headerHash.CopyTo(headerHashRev);
        headerHashRev = headerHashRev.Reverse().ToArray();
        var headerValueRev = new uint256(headerHashRev);


        //testuint
        var uint256hash = new uint256(headerHashRev);
        var uint256hashHex = new uint256(headerValueHex);
        var w2 = new Target(new uint256(headerHashRev));
        var d1 = new Target(new uint256(headerValueHex));
        //miner difficult configuration

        var shareTargetBits = GetBitsFromDifficult(context.Difficulty);
        var shareTarget = new Target(shareTargetBits);

        var difficulty = GetDifficulty(new Target(headerValue));
        var difficulty2 = GetDifficulty(new Target(headerHash.ToBigInteger()));

        var blockTargetValueReversed = new uint256(blockTargetValue.ToBytes().Reverse().ToArray());
        var targetBlockTargetValue = new Target(blockTargetValue);
        var targetBlockTargetValueReversed = new Target(blockTargetValueReversed);

        var WisBlockCandidateYY = headerValueRev <= blockTargetValueReversed;
        var WisBlockCandidateYYX = headerValue <= blockTargetValueReversed;
        var WisBlockCandidateXX = headerValue <= blockTargetValue;
        var WisBlockCandidateXXY = headerValueRev <= blockTargetValue;

        bool atLeastOneTrue2 = new[] { WisBlockCandidateYY, WisBlockCandidateYYX, WisBlockCandidateXX, WisBlockCandidateXXY }.Any();
        if(atLeastOneTrue2)
        {
            var isTrue = true;
        }

        // calc share-diff
        // var shareDiff = (double) new BigRational(ZEEVConstants.Diff1, GetDifficulty(header.Bits)) * shareMultiplier;
        var shareDiff = (double) new BigRational(ZEEVConstants.Diff1, headerHash.ToBigInteger()) * shareMultiplier; //
        var shareDiff2Rev = (double) new BigRational(ZEEVConstants.Diff1, new Span<byte>(headerHashRev).ToBigInteger()) * shareMultiplier; //
     //   var shareDiff3 = (double) new BigRational(ZEEVConstants.Diff1, GetDifficulty(new Target(headerHash.ToBigInteger()))) * shareMultiplier;
        //headerHash.Reverse();
        //var shareDiffRev2 = (double) new BigRational(ZEEVConstants.Diff1, headerHash.ToBigInteger()) * shareMultiplier;
        //var shareDiffRev2Rev = (double) new BigRational(ZEEVConstants.Diff1, new Span<byte>(headerHashRev).ToBigInteger()) * shareMultiplier;
        //var shareDiffRev3 = (double) new BigRational(ZEEVConstants.Diff1, GetDifficulty(new Target(headerHash.ToBigInteger()))) * shareMultiplier;

        var hashVal = headerHash.ToBigInteger();
        var hashValRev = new Span<byte>(headerHashRev).ToBigInteger();
        var diffff = Math.Pow(2, 32);
        var ssssss = BigInteger.Parse("00ffff0000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
        var headerHashDef = GetDifficulty(new Target(headerHash.ToBigInteger()));
        var headerHashDefRev = GetDifficulty(new Target(new Span<byte>(headerHashRev).ToBigInteger()));
        var headerDiff = GetDifficulty(header.Bits);

        var stratumDifficulty = context.Difficulty;
        //var ratio = shareDiff / stratumDifficulty;
        var ratio = (double) shareDiff / stratumDifficulty;
        var ratio2Rev = (double) shareDiff2Rev / stratumDifficulty;
        //var ratio3 = shareDiff3 / stratumDifficulty;
        //var ratioRev2 = shareDiffRev2 / stratumDifficulty;
        //var ratioRev3 = shareDiffRev3 / stratumDifficulty;

        //var xx = headerHash.ToBigInteger();
        //var xxx = BigInteger.Parse("00ffff0000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
        //var x = new BigInteger(blockTargetValue.ToBytes());
        
        // check if the share meets the much harder block difficulty (block candidate)

        try
        {
            var targetHeader = new Target(headerValue);
            targetBlockTargetValue = new Target(blockTargetValue);
            targetBlockTargetValueReversed = new Target(blockTargetValueReversed);
        }
        catch(Exception)
        {

            throw;
        }
        var isBlockCandidate = headerValueRev <= blockTargetValue;
        if(isBlockCandidate)
        {
            isBlockCandidate = true;
        }

        var isBlockCandidate2 = headerValueRev <= blockTargetValueReversed;
        if(isBlockCandidate2)
        {
            isBlockCandidate = true;
        }

        var isBlockCandidate3 = headerValue <= blockTargetValue;
        if (isBlockCandidate3)
        {
            isBlockCandidate = true;
        }

        var isBlockCandidate4 = headerValue <= blockTargetValueReversed;
        if(isBlockCandidate4)
        {
            isBlockCandidate = true;
        }

        // test if share meets at least workers current difficulty
        if(!isBlockCandidate && ratio < 0.99)
        {
            // check if share matched the previous difficulty from before a vardiff retarget
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;

                if(ratio < 0.99)
                    throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                // use previous difficulty
                stratumDifficulty = context.PreviousDifficulty.Value;
            }

            else
                throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");
        }

        var result = new Share
        {
            BlockHeight = BlockTemplate.Height,
            NetworkDifficulty = Difficulty,
            Difficulty = stratumDifficulty / shareMultiplier,
        };

        if(isBlockCandidate)
        {
            result.IsBlockCandidate = true;
            result.BlockHash = headerValue.ToString();

            var headerBytes = header.ToBytes();
            var blockBytes = SerializeBlock(headerBytes, coinbase);
            var blockHex = blockBytes.ToHexString();

            return (result, blockHex);
        }

        return (result, null);
    }

    protected virtual byte[] SerializeCoinbase(string extraNonce1, string extraNonce2)
    {
        var extraNonce1Bytes = extraNonce1.HexToByteArray();
        var extraNonce2Bytes = extraNonce2.HexToByteArray();

        using(var stream = new MemoryStream())
        {
            stream.Write(coinbaseInitial);
            stream.Write(extraNonce1Bytes);
            stream.Write(extraNonce2Bytes);
            stream.Write(coinbaseFinal);

            return stream.ToArray();
        }
    }

    protected virtual byte[] SerializeBlock(byte[] header, byte[] coinbase)
    {
        var rawTransactionBuffer = BuildRawTransactionBuffer();
        var transactionCount = (uint) BlockTemplate.Transactions.Length + 1; // +1 for prepended coinbase tx

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            bs.ReadWrite(ref header);
            bs.ReadWriteAsVarInt(ref transactionCount);

            bs.ReadWrite(ref coinbase);
            bs.ReadWrite(ref rawTransactionBuffer);

            // POS coins require a zero byte appended to block which the daemon replaces with the signature
            if(isPoS)
                bs.ReadWrite((byte) 0);

            return stream.ToArray();
        }
    }

    protected virtual byte[] BuildRawTransactionBuffer()
    {
        using(var stream = new MemoryStream())
        {
            foreach(var tx in BlockTemplate.Transactions)
            {
                var txRaw = tx.Data.HexToByteArray();
                stream.Write(txRaw);
            }

            return stream.ToArray();
        }
    }

    #region Masternodes

    protected MasterNodeBlockTemplateExtra masterNodeParameters;

    protected virtual Money CreateMasternodeOutputs(Transaction tx, Money reward)
    {
        if(masterNodeParameters.Masternode != null)
        {
            Masternode[] masternodes;

            // Dash v13 Multi-Master-Nodes
            if(masterNodeParameters.Masternode.Type == JTokenType.Array)
                masternodes = masterNodeParameters.Masternode.ToObject<Masternode[]>();
            else
                masternodes = new[] { masterNodeParameters.Masternode.ToObject<Masternode>() };

            if(masternodes != null)
            {
                foreach(var masterNode in masternodes)
                {
                    if(!string.IsNullOrEmpty(masterNode.Payee))
                    {
                        var payeeDestination = ZEEVUtils.AddressToDestination(masterNode.Payee, network);
                        var payeeReward = masterNode.Amount;

                        tx.Outputs.Add(payeeReward, payeeDestination);
                        reward -= payeeReward;
                    }
                }
            }
        }

        if(masterNodeParameters.SuperBlocks is { Length: > 0 })
        {
            foreach(var superBlock in masterNodeParameters.SuperBlocks)
            {
                var payeeAddress = ZEEVUtils.AddressToDestination(superBlock.Payee, network);
                var payeeReward = superBlock.Amount;

                tx.Outputs.Add(payeeReward, payeeAddress);
                reward -= payeeReward;
            }
        }

        if(!coin.HasPayee && !string.IsNullOrEmpty(masterNodeParameters.Payee))
        {
            var payeeAddress = ZEEVUtils.AddressToDestination(masterNodeParameters.Payee, network);
            var payeeReward = masterNodeParameters.PayeeAmount;

            tx.Outputs.Add(payeeReward, payeeAddress);
            reward -= payeeReward;
        }

        return reward;
    }

    #endregion // Masternodes

    #region Founder

    protected FounderBlockTemplateExtra founderParameters;

    protected virtual Money CreateFounderOutputs(Transaction tx, Money reward)
    {
        if (founderParameters.Founder != null)
        {
            Founder[] founders;
            if (founderParameters.Founder.Type == JTokenType.Array)
                founders = founderParameters.Founder.ToObject<Founder[]>();
            else
                founders = new[] { founderParameters.Founder.ToObject<Founder>() };

            if(founders != null)
            {
                foreach(var Founder in founders)
                {
                    if(!string.IsNullOrEmpty(Founder.Payee))
                    {
                        var payeeAddress = ZEEVUtils.AddressToDestination(Founder.Payee, network);
                        var payeeReward = Founder.Amount;

                        tx.Outputs.Add(payeeReward, payeeAddress);
                        reward -= payeeReward;
                    }
                }
            }
        }

        return reward;
    }

    #endregion // Founder

    #region Minerfund

    protected MinerFundTemplateExtra minerFundParameters;

    protected virtual Money CreateMinerFundOutputs(Transaction tx, Money reward)
    {
        var payeeReward = minerFundParameters.MinimumValue;

        if (!string.IsNullOrEmpty(minerFundParameters.Addresses?.FirstOrDefault()))
        {
            var payeeAddress = ZEEVUtils.AddressToDestination(minerFundParameters.Addresses[0], network);
            tx.Outputs.Add(payeeReward, payeeAddress);
        }

        reward -= payeeReward;

        return reward;
    }

    #endregion // Founder

    #region API-Surface

    public BlockTemplate BlockTemplate { get; protected set; }
    public double Difficulty { get; protected set; }

    public string JobId { get; protected set; }

    public void Init(BlockTemplate blockTemplate, string jobId,
        PoolConfig pc, ZEEVPoolConfigExtra extraPoolConfig,
        ClusterConfig cc, IMasterClock clock,
        IDestination poolAddressDestination, Network network,
        bool isPoS, double shareMultiplier, IHashAlgorithm coinbaseHasher,
        IHashAlgorithm headerHasher, IHashAlgorithm blockHasher)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(pc);
        Contract.RequiresNonNull(cc);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(poolAddressDestination);
        Contract.RequiresNonNull(coinbaseHasher);
        Contract.RequiresNonNull(headerHasher);
        Contract.RequiresNonNull(blockHasher);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        coin = pc.Template.As<ZEEVCoinTemplate>();
        networkParams = coin.GetNetwork(network.ChainName);
        txVersion = coin.CoinbaseTxVersion;
        this.network = network;
        this.clock = clock;
        this.poolAddressDestination = poolAddressDestination;
        BlockTemplate = blockTemplate;
        JobId = jobId;

        var coinbaseString = !string.IsNullOrEmpty(cc.PaymentProcessing?.CoinbaseString) ?
            cc.PaymentProcessing?.CoinbaseString.Trim() : "Miningcore";

        scriptSigFinalBytes = new Script(Op.GetPushOp(Encoding.UTF8.GetBytes(coinbaseString))).ToBytes();

        Difficulty = new Target(System.Numerics.BigInteger.Parse(BlockTemplate.Target, NumberStyles.HexNumber)).Difficulty;

        extraNoncePlaceHolderLength = ZEEVConstants.ExtranoncePlaceHolderLength;
        this.isPoS = isPoS;
        this.shareMultiplier = shareMultiplier;

        txComment = !string.IsNullOrEmpty(extraPoolConfig?.CoinbaseTxComment) ?
            extraPoolConfig.CoinbaseTxComment : coin.CoinbaseTxComment;

        if(coin.HasMasterNodes)
        {
            masterNodeParameters = BlockTemplate.Extra.SafeExtensionDataAs<MasterNodeBlockTemplateExtra>();

            if((coin.Symbol == "RTM") || (coin.Symbol == "THOON") || (coin.Symbol == "YERB") || (coin.Symbol == "BTRM"))
            {
                if(masterNodeParameters.Extra?.ContainsKey("smartnode") == true)
                {
                    masterNodeParameters.Masternode = JToken.FromObject(masterNodeParameters.Extra["smartnode"]);
                }
            }

            if(!string.IsNullOrEmpty(masterNodeParameters.CoinbasePayload))
            {
                txVersion = 3;
                const uint txType = 5;
                txVersion += txType << 16;
            }
        }

        if(coin.HasPayee)
            payeeParameters = BlockTemplate.Extra.SafeExtensionDataAs<PayeeBlockTemplateExtra>();

        if (coin.HasFounderFee)
            founderParameters = BlockTemplate.Extra.SafeExtensionDataAs<FounderBlockTemplateExtra>();

        if (coin.HasMinerFund)
            minerFundParameters = BlockTemplate.Extra.SafeExtensionDataAs<MinerFundTemplateExtra>("coinbasetxn", "minerfund");

        this.coinbaseHasher = coinbaseHasher;
        this.headerHasher = headerHasher;
        this.blockHasher = blockHasher;

        //if(!string.IsNullOrEmpty(BlockTemplate.Target))
        //{
        //    blockTargetValue = new uint256(BlockTemplate.Target);
        //}
        //else
        //{
        var tmp = new Target(BlockTemplate.Bits.HexToByteArray().ToArray());
        blockTargetValue = tmp.ToUInt256();
        //}

        //tmp = new Target("1c00ffff".HexToByteArray().ToArray());
        //blockTargetValue = tmp.ToUInt256();

        //var sssss = BlockTemplate.Bits.HexToByteArray();
        //var por = new BigInteger(sssss.Reverse().ToArray());

        var bitsBytes = BlockTemplate.Bits.HexToByteArray();
        //blockTargetValue = new Target(por).ToUInt256();


        //Array.Reverse(bitsBytes);

        //var tmpc = new Target(BlockTemplate.Bits.HexToByteArray());
        //blockTargetValue = tmpc.ToUInt256();
        //var bytesssss = blockTargetValue.ToBytes();
        //var bytesssssR = blockTargetValue.ToBytes().Reverse().ToArray();

        //var xx2 = new uint256(bytesssss);
        //var x4 = new uint256(bytesssssR);
        //var xx = new uint256(BlockTemplate.Target);

        //var ssssss = BigInteger.Parse("000000000000000000000000000000000000000000000000000000001d00ffff", NumberStyles.HexNumber);
        //var ssssss2 = BigInteger.Parse("00000000ffff0000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
        //var ssssss3 = BigInteger.Parse("0000000000000000000000000000000000000000000000000000ffff00000000", NumberStyles.HexNumber);

        //    previousBlockHashReversedHex = BlockTemplate.PreviousBlockhash
        //.HexToByteArray()
        //.ReverseByteOrder()
        //.ToHexString();

        //string[] chunks = new string[8];
        //for(int i = 0; i < 8; i++)
        //{
        //    chunks[i] = BlockTemplate.PreviousBlockhash.Substring(i * 8, 8);
        //}
        //Array.Reverse(chunks);
        //previousBlockHashReversedHex = string.Concat(chunks);

        //reverse total
        byte[] byteArray = new byte[BlockTemplate.PreviousBlockhash.Length / 2];
        for(int i = 0; i < byteArray.Length; i++)
        {
            byteArray[i] = Convert.ToByte(BlockTemplate.PreviousBlockhash.Substring(i * 2, 2), 16);
        }
        Array.Reverse(byteArray);
        previousBlockHashReversedHex = BitConverter.ToString(byteArray).Replace("-", "").ToLower();

        var now = ((DateTimeOffset) clock.Now).ToUnixTimeSeconds();
        BuildCoinbase(false, now);
        BuildMerkleBranches();

        var txHEX = coinbaseInitial.Concat(coinbaseFinal).ToHexString();
        var txInitialHEX = coinbaseInitial.ToHexString();
        var txFinalHEX = coinbaseFinal.ToHexString();
        var coinbaseHashHEX = coinbaseHash.ToHexString();

        var logger = LogUtil.GetPoolScopedLogger(typeof(ZEEVJob), "Zeev");

        logger.Info(() => $"txHEX {txHEX}");
        logger.Info(() => $"txInitialHEX {txInitialHEX}");
        logger.Info(() => $"txFinalHEX {txFinalHEX}");
        logger.Info(() => $"coinbaseHashHEX {coinbaseHashHEX}");
        logger.Info(() => $"merkleRootHashHex {merkleRootHashHex}");

        BuildCoinbase(true, now);

        var curTimeBytes = BitConverter.GetBytes(BlockTemplate.CurTime); //getting BE
        //var curTimeHex = (curTimeBytes.ToHexString());
        //var i1 = uint.Parse(curTimeHex, NumberStyles.HexNumber);
        Array.Reverse(curTimeBytes);
        //var i2 = uint.Parse(curTimeBytes.ToHexString(), NumberStyles.HexNumber);


        //int value = Convert.ToInt32("00000003");
        uint num = uint.Parse("00000003", System.Globalization.NumberStyles.AllowHexSpecifier);
        uint num2 = uint.Parse("20000000", System.Globalization.NumberStyles.AllowHexSpecifier);
        // var s = uint.Parse("00000003")

        jobParams = new object[]
        {
            JobId,
            BlockTemplate.PreviousBlockhash, //"5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0"
            merkleRootHashHex, //"28b17095216d5e211ba1f61031416a51efca54eacb8c9059440c4671b0625bbe", //coinbaseInitialHex,
            coinbaseFinalHex, //"59919422c20530ece2b328adf63ec3f35a10e79375731687a81dfa7cd83a24e7",
            BlockTemplate.TreeRoot, //BlockTemplate.TreeRoot,
            BlockTemplate.ReservedRoot, //BlockTemplate.ReservedRoot,
            BlockTemplate.Version.ToStringHex8(),
            bitsBytes.ToHexString(),
            BlockTemplate.CurTime.ToStringHex8()
        };

        var testB1 = "0000000000a5e40e8ba291bd7e8649747fa7fb8a7af39f5bacdb7433cd2f5971".HexToByteArray();
        var testB2 = "0000000000a5e40e8ba291bd7e8649747fa7fb8a7af39f5bacdb7433cd2f5971".HexToReverseByteArray();
        var w1 = new Target(new uint256(testB1));
        var w2 = new Target(new uint256(testB2));
        var d1 = new Target(new uint256("0000000000a5e40e8ba291bd7e8649747fa7fb8a7af39f5bacdb7433cd2f5971"));
        var d2 = new Target(new uint256(testB2.ToHexString()));
        //        Job ID -Used so that stratum can match shares with the client that mined them.
        //Hash of previous block -Needed in the header.
        //Merkle Tree -This is a list of merkle branches that are hashed along with the newly formed coinbase transaction to get the merkle root.
        //Witness Root -The witness root
        //Tree Root -The root of the Urkel tree that maintains name states.Needed for the block header.
        //Reserved Root - A root reserved for future use. Needed for block header.
        //Block Version - Needed for the block header.
        //nBits - Needed for the block header.This is the current network difficulty.
        //nTime - Needed for block header.
    }

    public object GetJobParams(bool isNew)
    {
        // jobParams[^1] = isNew;
        return jobParams;
    }

    public virtual (Share Share, string BlockHex) ProcessShare(StratumConnection worker,
        string extraNonce2, string nTime, string nonce, string versionBits = null)
    {
        Contract.RequiresNonNull(worker);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(extraNonce2));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nTime));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));

        var context = worker.ContextAs<ZEEVWorkerContext>();

        // validate nTime
        if(nTime.Length != 8)
            throw new StratumException(StratumError.Other, "incorrect size of ntime");

        var nTimeInt = uint.Parse(nTime, NumberStyles.HexNumber);
        if(nTimeInt < BlockTemplate.CurTime || nTimeInt > ((DateTimeOffset) clock.Now).ToUnixTimeSeconds() + 7200)
            throw new StratumException(StratumError.Other, "ntime out of range");

        // validate nonce
        if(nonce.Length != 8)
            throw new StratumException(StratumError.Other, "incorrect size of nonce");

        var nonceInt = uint.Parse(nonce, NumberStyles.HexNumber);

        // validate version-bits (overt ASIC boost)
        uint versionBitsInt = 0;

        if(context.VersionRollingMask.HasValue && versionBits != null)
        {
            versionBitsInt = uint.Parse(versionBits, NumberStyles.HexNumber);

            // enforce that only bits covered by current mask are changed by miner
            if((versionBitsInt & ~context.VersionRollingMask.Value) != 0)
                throw new StratumException(StratumError.Other, "rolling-version mask violation");
        }

        // dupe check
        if(!RegisterSubmit(context.ExtraNonce1, extraNonce2, nTime, nonce))
            throw new StratumException(StratumError.DuplicateShare, "duplicate share");

        return ProcessShareInternal(worker, extraNonce2, nTimeInt, nonce, versionBitsInt);
    }

    #endregion // API-Surface

    private static uint ToUInt32BigEndian(byte[] bytes, int startIndex)
    {
        if(BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes, startIndex, 4);
        }

        return BitConverter.ToUInt32(bytes, startIndex);
    }

    public static BigInteger Double256(byte[] target)
    {
        if(target.Length != 32)
        {
            throw new ArgumentException("Target length must be 32 bytes");
        }

        BigInteger n = 0;
        BigInteger hi, lo;


        hi = ToUInt32BigEndian(target, 0);
        lo = ToUInt32BigEndian(target, 4);
        n += (hi * 0x100000000 + lo) * BigInteger.Parse("1000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);

        hi = ToUInt32BigEndian(target, 8);
        lo = ToUInt32BigEndian(target, 12);
        n += (hi * 0x100000000 + lo) * BigInteger.Parse("100000000000000000000000000000000", NumberStyles.HexNumber);

        hi = ToUInt32BigEndian(target, 16);
        lo = ToUInt32BigEndian(target, 20);
        n += (hi * 0x100000000 + lo) * BigInteger.Parse("10000000000000000", NumberStyles.HexNumber);

        hi = ToUInt32BigEndian(target, 24);
        lo = ToUInt32BigEndian(target, 28);
        n += (hi * 0x100000000 + lo) * BigInteger.Parse("1", NumberStyles.HexNumber);

        return n;
    }

    public static BigInteger GetDifficulty(Target target)
    {
        var d = BigInteger.Parse("00000000ffff0000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
        var targetBytes = target.ToUInt256().ToBytes();
        var n = Double256(targetBytes);

        if(n == 0)
            return d;

        return BigInteger.Divide(d, n);
    }
}
