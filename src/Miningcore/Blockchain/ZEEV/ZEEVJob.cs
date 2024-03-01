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
    protected byte[] coinbaseInitial;
    protected byte[] merkleRootHash;
    protected string merkleRootHashHex;
    protected byte[] witnessRootHash;
    protected string witnessRootHashHex;
    protected byte[] coinbaseHash;

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
            .Select(tx => tx.TxId
                .HexToByteArray()
                .ReverseInPlace())
            .ToArray();

        var witnessHashes = BlockTemplate.Transactions
            .Select(tx => tx.Hash
                .HexToByteArray()
                .ReverseInPlace())
            .ToArray();

        var mt = new ZEEVMerkleTree(transactionHashes);
        var witnessMt = new ZEEVMerkleTree(witnessHashes);

        var first = coinbaseHash;
        var blake2bConfig = new Blake2BConfig();
        blake2bConfig.OutputSizeInBytes = 32;

        foreach(var step in mt.Steps)
        {
            first = Blake2B.ComputeHash(first.Concat(step).ToArray(), blake2bConfig);
        }

        var merkleRoot = mt.WithFirst(coinbaseHash).ToNewReverseArray();
        merkleRootHash = merkleRoot;
        merkleRootHashHex = merkleRoot.ToHexString();

        first = new uint256().ToBytes();
        foreach(var step in witnessMt.Steps)
        {
            first = Blake2B.ComputeHash(first.Concat(step).ToArray(), blake2bConfig);
        }

        var witnessRoot = witnessMt.WithFirst(new uint256().ToBytes()).ToNewReverseArray();
        witnessRootHash = witnessRoot;
        witnessRootHashHex = witnessRoot.ToHexString();
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
        // Build version
        var version = BlockTemplate.Version;

        // Overt-ASIC boost
        if(versionMask.HasValue && versionBits.HasValue)
            version = (version & ~versionMask.Value) | (versionBits.Value & versionMask.Value);

        Array.Resize(ref extraNonce, 24);

#pragma warning disable 618
        var blockHeader = new ZEEVBlockHeader
#pragma warning restore 618
        {
            Version = unchecked((int) version),
            Bits = new Target(Encoders.Hex.DecodeData(BlockTemplate.Bits)),
            HashPrevBlock = uint256.Parse(BlockTemplate.PreviousBlockhash),
            HashMerkleRoot = new uint256(merkleRootHash, false),
            BlockTime = DateTimeOffset.FromUnixTimeSeconds(nTime),
            Nonce = nonce,
            HashReservedRoot = uint256.Parse("0000000000000000000000000000000000000000000000000000000000000000"),
            HashTreeRoot = uint256.Parse("0000000000000000000000000000000000000000000000000000000000000000"),
            HashWitnessRoot = new uint256(witnessRootHash, false), 
            HashMask = uint256.Parse("0000000000000000000000000000000000000000000000000000000000000000"), 
            ExtraNonce = extraNonce
        };

        return blockHeader;
    }

    //public static BigInteger Div(BigInteger x, double y)
    //{
    //    var yb = new BigInteger(y);

    //    if(Math.Abs(y) < double.Epsilon)
    //    {
    //        throw new ArgumentException("Division by zero is not allowed.");
    //    }

    //    BigInteger q = (BigInteger) (x / yb);

    //    if(x >= 0)
    //    {
    //        return q;
    //    }

    //    BigInteger r = x - (BigInteger) (q * yb);

    //    if(r < 0)
    //    {
    //        if(yb < 0)
    //            q += 1;
    //        else
    //            q -= 1;
    //    }

    //    return q;
    //}

    //static byte[] ToCompactByteArray(BigInteger num)
    //{
    //    if(num.IsZero)
    //        return new byte[] { 0 };

    //    int exponent = num.ToByteArray().Length;
    //    int mantissa;

    //    if(exponent <= 3)
    //    {
    //        mantissa = (int) num;
    //        mantissa <<= 8 * (3 - exponent);
    //    }
    //    else
    //    {
    //        mantissa = (int) (num >> 8 * (exponent - 3));
    //    }

    //    if((mantissa & 0x800000) != 0)
    //    {
    //        mantissa >>= 8;
    //        exponent += 1;
    //    }

    //    int compact = (exponent << 24) | mantissa;

    //    if(num.Sign < 0)
    //        compact |= 0x800000;

    //    compact = (int) ((uint) compact);

    //    // Convert compact to a byte array
    //    List<byte> byteArray = new List<byte>();
    //    for(int i = 0; i < 4; i++)
    //    {
    //        byteArray.Insert(0, (byte) ((compact & (0xFF << (i * 8))) >> (i * 8)));
    //    }
    //    return byteArray.ToArray();
    //}

    //public static byte[] GetBitsFromDifficult(double difficulty)
    //{
    //    BigInteger max = BigInteger.Parse("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", NumberStyles.HexNumber);

    //    var s = Div(max, difficulty);
    //    var cmpct = ToCompactByteArray(s);

    //    return cmpct;
    //}

    protected virtual (Share Share, string BlockHex) ProcessShareInternal(
        StratumConnection worker, string extraNonce2, uint nTime, string nonceString, uint? versionBits)
    {
        uint nonce = uint.Parse(nonceString, NumberStyles.HexNumber);
        // var nonceBytes = nonceString.HexToByteArray();

        var context = worker.ContextAs<ZEEVWorkerContext>();
        var extraNonce1 = context.ExtraNonce1;

        // build coinbase
        var coinbase = SerializeCoinbase(extraNonce1, extraNonce2);
        Span<byte> coinbaseHash = stackalloc byte[32];
        coinbaseHasher.Digest(coinbase, coinbaseHash);

        var header = SerializeHeader(coinbaseHash, nTime, nonce, (extraNonce1 + extraNonce2).HexToByteArray(), context.VersionRollingMask, versionBits);
        var headerBytesMiner = header.ToMiner();
        //var headerBytesX = header.ToBytes();
        //var headerBytesHex = Encoders.Hex.EncodeData(headerBytesX);
        //var headerBytesMinerHex = Encoders.Hex.EncodeData(headerBytesMiner);
        Span<byte> headerHash = stackalloc byte[32];
        ((Handshake) headerHasher).Digest(headerBytesMiner, out headerHash, (ulong) nTime, BlockTemplate, coin, networkParams);
        //var headerValueHex = Encoders.Hex.EncodeData(headerHash);
        var headerValue = new uint256(headerHash);
        //var headerHashRev = new byte[32];
        //headerHash.CopyTo(headerHashRev);
        //headerHashRev = headerHashRev.Reverse().ToArray();
        //var headerValueRev = new uint256(headerHashRev);

        // calc share-diff
        var shareDiff = (double) new BigRational(ZEEVConstants.Diff1, headerHash.ToBigInteger()) * shareMultiplier; 
        //var shareDiff2Rev = (double) new BigRational(ZEEVConstants.Diff1, new Span<byte>(headerHashRev).ToBigInteger()) * shareMultiplier; 

        var stratumDifficulty = context.Difficulty;
        var ratio = (double) shareDiff / stratumDifficulty;
        //var ratio2Rev = (double) shareDiff2Rev / stratumDifficulty;

        var isBlockCandidate = headerValue <= blockTargetValue;
        if (isBlockCandidate)
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

        var tmp = new Target(BlockTemplate.Bits.HexToByteArray().ToArray());
        blockTargetValue = tmp.ToUInt256();

        var bitsBytes = BlockTemplate.Bits.HexToByteArray();

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

        //var txHEX = coinbaseInitial.Concat(coinbaseFinal).ToHexString();
        //var txInitialHEX = coinbaseInitial.ToHexString();
        //var txFinalHEX = coinbaseFinal.ToHexString();
        //var coinbaseHashHEX = coinbaseHash.ToHexString();

        BuildCoinbase(true, now);

        var curTimeBytes = BitConverter.GetBytes(BlockTemplate.CurTime);
        Array.Reverse(curTimeBytes);

        jobParams = new object[]
        {
            JobId,
            BlockTemplate.PreviousBlockhash,
            merkleRootHashHex,
            witnessRootHashHex,
            BlockTemplate.TreeRoot,
            BlockTemplate.ReservedRoot,
            BlockTemplate.Version.ToStringHex8(),
            bitsBytes.ToHexString(),
            BlockTemplate.CurTime.ToStringHex8()
        };
    }

    public object GetJobParams(bool isNew)
    {
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

        //var nonceInt = uint.Parse(nonce, NumberStyles.HexNumber);

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

    //private static uint ToUInt32BigEndian(byte[] bytes, int startIndex)
    //{
    //    if(BitConverter.IsLittleEndian)
    //    {
    //        Array.Reverse(bytes, startIndex, 4);
    //    }

    //    return BitConverter.ToUInt32(bytes, startIndex);
    //}

    //public static BigInteger Double256(byte[] target)
    //{
    //    if(target.Length != 32)
    //    {
    //        throw new ArgumentException("Target length must be 32 bytes");
    //    }

    //    BigInteger n = 0;
    //    BigInteger hi, lo;


    //    hi = ToUInt32BigEndian(target, 0);
    //    lo = ToUInt32BigEndian(target, 4);
    //    n += (hi * 0x100000000 + lo) * BigInteger.Parse("1000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);

    //    hi = ToUInt32BigEndian(target, 8);
    //    lo = ToUInt32BigEndian(target, 12);
    //    n += (hi * 0x100000000 + lo) * BigInteger.Parse("100000000000000000000000000000000", NumberStyles.HexNumber);

    //    hi = ToUInt32BigEndian(target, 16);
    //    lo = ToUInt32BigEndian(target, 20);
    //    n += (hi * 0x100000000 + lo) * BigInteger.Parse("10000000000000000", NumberStyles.HexNumber);

    //    hi = ToUInt32BigEndian(target, 24);
    //    lo = ToUInt32BigEndian(target, 28);
    //    n += (hi * 0x100000000 + lo) * BigInteger.Parse("1", NumberStyles.HexNumber);

    //    return n;
    //}

    //public static BigInteger GetDifficulty(Target target)
    //{
    //    var d = BigInteger.Parse("00000000ffff0000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
    //    var targetBytes = target.ToUInt256().ToBytes();
    //    var n = Double256(targetBytes);

    //    if(n == 0)
    //        return d;

    //    return BigInteger.Divide(d, n);
    //}
}
