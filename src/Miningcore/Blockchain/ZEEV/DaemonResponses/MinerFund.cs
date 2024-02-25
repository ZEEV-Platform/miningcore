using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Miningcore.Blockchain.ZEEV.DaemonResponses
{
    public class MinerFundTemplateExtra
    {
        public string[] Addresses { get; set; }
        public ulong MinimumValue { get; set; }
    }
}
