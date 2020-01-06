package cn.hba.audit.flume.soc.log.logss;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 山石
 *
 * @author wbw
 * @date 2019/9/6 11:18
 */

public class SyslogParseSs implements SyslogParse {


    @Override
    public Object parse(String body) {
        return BastionSsHost.parse(body);
    }

    public static void main(String[] args) {
        String sys = "<189>Oct 24 15:23:37 1304415172000634(root) 43240507 Event@NET: ARP entry 172.17.211.26 0000.0000.0000 is deleted for timeout";

        JSONObject object = new JSONObject();
        object.put("syslog",sys);
        System.out.println(JSONUtil.parseObj(new SyslogParseSs().parse(object.toString())).toJSONString(2));
    }
}
