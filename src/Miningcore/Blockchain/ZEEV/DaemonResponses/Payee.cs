using Newtonsoft.Json;

namespace Miningcore.Blockchain.ZEEV.DaemonResponses;

public class PayeeBlockTemplateExtra
{
    public string Payee { get; set; }

    [JsonProperty("payee_amount")]
    public long? PayeeAmount { get; set; }
}
