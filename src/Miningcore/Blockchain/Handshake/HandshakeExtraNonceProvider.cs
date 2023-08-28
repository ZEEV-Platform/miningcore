namespace Miningcore.Blockchain.Handshake;

public class HandshakeExtraNonceProvider : ExtraNonceProviderBase
{
    public HandshakeExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, 4, clusterInstanceId)
    {
    }
}
