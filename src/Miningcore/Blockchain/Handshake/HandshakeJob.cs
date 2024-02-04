using System.Collections.Concurrent;
using System.Globalization;
using System.Numerics;
using System.Text;
using Miningcore.Blockchain.Handshake.Configuration;
using Miningcore.Blockchain.Handshake.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Handshake;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NBitcoin.DataEncoders;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Utilities;
using Contract = Miningcore.Contracts.Contract;
using Transaction = NBitcoin.Transaction;

namespace Miningcore.Blockchain.Handshake;

public class HandshakeJob
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
    protected HandshakeCoinTemplate coin;
    private HandshakeCoinTemplate.HandshakeNetworkParams networkParams;
    protected readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);
    protected uint256 blockTargetValue;
    protected byte[] coinbaseFinal;
    protected string coinbaseFinalHex;
    protected byte[] coinbaseInitial;
    protected string coinbaseInitialHex;
    protected string[] merkleBranchesHex;
    protected MerkleTree mt;

    ///////////////////////////////////////////
    // GetJobParams related properties

    protected object[] jobParams;
    protected string previousBlockHashReversedHex;
    protected Money rewardToPool;
    protected Transaction txOut;

    // serialization constants
    protected byte[] scriptSigFinalBytes;

    protected static byte[] sha256Empty = new byte[32];
    protected uint txVersion = 1u; // transaction version (currently 1) - see https://en.Handshake.it/wiki/Transaction

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

        mt = new MerkleTree(transactionHashes);

        merkleBranchesHex = mt.Steps
            .Select(x => x.ToHexString())
            .ToArray();
    }

    protected virtual void BuildCoinbase()
    {
        // generate script parts
        var sigScriptInitial = GenerateScriptSigInitial();
        var sigScriptInitialBytes = sigScriptInitial.ToBytes();

        var sigScriptLength = (uint) (
            sigScriptInitial.Length +
            extraNoncePlaceHolderLength +
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

    protected virtual Script GenerateScriptSigInitial()
    {
        var now = ((DateTimeOffset) clock.Now).ToUnixTimeSeconds();

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

            tx.Outputs.Add(payeeReward, HandshakeUtils.AddressToDestination(payeeParameters.Payee, network));
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

    protected HandshakeBlockHeader SerializeHeader(Span<byte> coinbaseHash, uint nTime, uint nonce, byte[] extraNonce2, uint? versionMask, uint? versionBits)
    {
        var headerHex2 = "a6496be42fe1b065000000000000000000000005b4490d1678b73c066ed15b6cbe0e98f684612504ffa4f97e34059276d78aa47040ba328b408416b61c80ac212681e1948ac2622705af27f301fcaf2eb1143da20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffd4f0144d43f2d8bb5d0da049911c392ea51e8463c5e74c2ae51b70d3016f6ae037061a67848020dee27740f93d8f9a937a1912be6068e77adb85eb43cd43d000000005a6407190000000000000000000000000000000000000000000000000000000000000000";
        var header = Enumerable.Range(0, headerHex2.Length)
             .Where(x => x % 2 == 0)
             .Select(x => Convert.ToByte(headerHex2.Substring(x, 2), 16))
             .ToArray();

        var test = new HandshakeBlockHeader(headerHex2);
        //var testBytes = test.ToBytes();
        //var testBytesMiner = test.ToMiner();
        //var testHex = Encoders.Hex.EncodeData(testBytes);
        //var testHexMiner = Encoders.Hex.EncodeData(testBytesMiner);

        // build merkle-root
        var merkleRoot = mt.WithFirst(coinbaseHash.ToArray());

        //    return test;
        // Build version
        var version = BlockTemplate.Version;

        // Overt-ASIC boost
        if(versionMask.HasValue && versionBits.HasValue)
            version = (version & ~versionMask.Value) | (versionBits.Value & versionMask.Value);

        Array.Resize(ref extraNonce2, 24);

#pragma warning disable 618
        var blockHeader = new HandshakeBlockHeader
#pragma warning restore 618
        {
            Version = unchecked((int) version),
            Bits = new Target(Encoders.Hex.DecodeData(BlockTemplate.Bits)),
            HashPrevBlock = uint256.Parse(BlockTemplate.PreviousBlockhash),
            HashMerkleRoot = new uint256(merkleRoot),
            BlockTime = DateTimeOffset.FromUnixTimeSeconds(nTime),
            Nonce = nonce,
            HashReservedRoot = new uint256(),
            HashTreeRoot = new uint256(),
            HashWitnessRoot = new uint256(),
            HashMask = new uint256(),
            ExtraNonce = extraNonce2
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

    protected virtual (Share Share, string BlockHex) ProcessShareInternal(
        StratumConnection worker, string extraNonce2, uint nTime, uint nonce, uint? versionBits)
    {
        var context = worker.ContextAs<HandshakeWorkerContext>();
        var extraNonce1 = context.ExtraNonce1;

        // build coinbase
        var coinbase = SerializeCoinbase(extraNonce1, extraNonce2);
        Span<byte> coinbaseHash = stackalloc byte[32];
        coinbaseHasher.Digest(coinbase, coinbaseHash);

        // hash block-header
        var header = SerializeHeader(coinbaseHash, nTime, nonce, (extraNonce1 + extraNonce2).HexToByteArray(), context.VersionRollingMask, versionBits);
        var headerBytesMiner = header.ToMiner();

        var headerBytesX = header.ToBytes();
        var headerBytesHex = Encoders.Hex.EncodeData(headerBytesX);
        var headerBytesMinerHex = Encoders.Hex.EncodeData(headerBytesMiner);
        Span<byte> headerHash = stackalloc byte[32];
        ((HandShake)headerHasher).Digest(headerBytesMiner, out headerHash, (ulong) nTime, BlockTemplate, coin, networkParams);
        var headerValue = new uint256(headerHash);

        // calc share-diff
        var shareDiff = (double)GetDifficulty(header.Bits);
        var shareDiff2 = (double) new BigRational(HandshakeConstants.Diff1, headerHash.ToBigInteger()) * shareMultiplier;
        var shareDiff3 = (double) GetDifficulty(new Target(headerHash.ToBigInteger()));
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff3 / stratumDifficulty;

        var xx = headerHash.ToBigInteger();
        var xxx = BigInteger.Parse("00ffff0000000000000000000000000000000000000000000000000000", NumberStyles.HexNumber);
        var x = new BigInteger(blockTargetValue.ToBytes());
        // check if the share meets the much harder block difficulty (block candidate)
        var isBlockCandidate = headerValue <= blockTargetValue;

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
                        var payeeDestination = HandshakeUtils.AddressToDestination(masterNode.Payee, network);
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
                var payeeAddress = HandshakeUtils.AddressToDestination(superBlock.Payee, network);
                var payeeReward = superBlock.Amount;

                tx.Outputs.Add(payeeReward, payeeAddress);
                reward -= payeeReward;
            }
        }

        if(!coin.HasPayee && !string.IsNullOrEmpty(masterNodeParameters.Payee))
        {
            var payeeAddress = HandshakeUtils.AddressToDestination(masterNodeParameters.Payee, network);
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
                        var payeeAddress = HandshakeUtils.AddressToDestination(Founder.Payee, network);
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
            var payeeAddress = HandshakeUtils.AddressToDestination(minerFundParameters.Addresses[0], network);
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
        PoolConfig pc, HandshakePoolConfigExtra extraPoolConfig,
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

        coin = pc.Template.As<HandshakeCoinTemplate>();
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

        extraNoncePlaceHolderLength = HandshakeConstants.ExtranoncePlaceHolderLength;
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

        if(!string.IsNullOrEmpty(BlockTemplate.Target))
            blockTargetValue = new uint256(BlockTemplate.Target);
        else
        {
            var tmp = new Target(BlockTemplate.Bits.HexToByteArray());
            blockTargetValue = tmp.ToUInt256();
        }

       // previousBlockHashReversedHex = BlockTemplate.PreviousBlockhash
       //     .HexToByteArray()
       //     .ReverseByteOrder()
       //     .ToHexString();

        BuildMerkleBranches();
        BuildCoinbase();

        //int value = Convert.ToInt32("00000003");
        uint num = uint.Parse("00000003", System.Globalization.NumberStyles.AllowHexSpecifier);
        uint num2 = uint.Parse("20000000", System.Globalization.NumberStyles.AllowHexSpecifier);
        // var s = uint.Parse("00000003")

        jobParams = new object[]
        {
            JobId,
            BlockTemplate.PreviousBlockhash,
            coinbaseInitialHex,
            coinbaseFinalHex,
            blockTemplate.TreeRoot,
            blockTemplate.ReservedRoot,
            BlockTemplate.Version.ToStringHex8(),
            BlockTemplate.Bits,
            BlockTemplate.CurTime.ToStringHex8()
        };
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

        var context = worker.ContextAs<HandshakeWorkerContext>();

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

        return ProcessShareInternal(worker, extraNonce2, nTimeInt, nonceInt, versionBitsInt);
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
