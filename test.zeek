global map:table[addr] of string;
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="http_response", $apply=set(SumStats::UNIQUE));
    local r2 = SumStats::Reducer($stream="404_response", $apply=set(SumStats::HLL_UNIQUE));
    SumStats::create([$name="404.attacker.detect",
                      $epoch=10min,
                      $reducers=set(r1,r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local R1 = result["http_response"];
                        local R2 = result["404_response"];
                        if(R2$num>2)
                                {
                                if((R2$num*1.0)/(R1$num*1.0)>0.2)
                                        {
                                        if((R2$hll_unique*1.0)/(R2$num*1.0)>0.5)
                                                {
                                                print fmt("%s is a scanner with %d scan attemps on %d urls",key$host,R2$num,R2$hll_unique);
                                                }
                                        }
                                }
                        }]);
    }
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	map[c$id$resp_h]=original_URI;
	}
event http_reply(c: connection, version: string, code: count, reason: string)
        {
        if(code==404)
                SumStats::observe("404_response",[$host=c$id$orig_h], [$str=map[c$id$resp_h]]);
        SumStats::observe("http_response",[$host=c$id$orig_h], [$str=map[c$id$resp_h]]);
        }
