namespace Miningcore.Persistence.Postgres.Entities;

public class Share
{
    public string PoolId { get; set; }
    public long BlockHeight { get; set; }
    public string Miner { get; set; }
    public string Worker { get; set; }
    public string UserAgent { get; set; }
    public decimal Difficulty { get; set; }
    public decimal NetworkDifficulty { get; set; }
    public string IpAddress { get; set; }
    public string Source { get; set; }
    public DateTime Created { get; set; }
}
