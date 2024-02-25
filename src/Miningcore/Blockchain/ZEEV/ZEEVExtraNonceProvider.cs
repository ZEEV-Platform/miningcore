namespace Miningcore.Blockchain.ZEEV;

public class ZEEVExtraNonceProvider : ExtraNonceProviderBase
{
    public ZEEVExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, 4, clusterInstanceId)
    {
    }
}
