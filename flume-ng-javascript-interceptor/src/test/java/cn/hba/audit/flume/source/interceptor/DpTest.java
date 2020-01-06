package cn.hba.audit.flume.source.interceptor;

import cn.hba.audit.flume.soc.log.logws.SyslogParseWs;
import cn.hutool.core.lang.Assert;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.junit.Test;

/**
 * @author wbw
 * @date 2019/9/9 14:19
 */
public class DpTest {
    @Test
    public void mmm(){
//        System.out.println("<134> 1 2013 Nov 26 11:46:51 172.254.100.10 FW - DSLITE:SessionbasedW".split(" ").length);
        String syslog = "<188>Dec  1 18:59:50 SecOS 2019-12-01 18:59:50 WAF: 192.168.100.133:60921->192.168.124.253 dip=192.168.109.98 devicename=SecOS url=/ method=GET args= flag_field= block_time=0 http_type= attack_field=2 profile_id=19 rule_id=40102 type=Signature Rule severity=0 action=CONTINUE referer= useragent= post= equipment=2 os=8 browser=1 |\n";
        SyslogParseWs ws = new SyslogParseWs();
        JSONObject obj = JSONUtil.createObj();
        obj.put("syslog",syslog);
        Object parse = ws.parse(obj.toString());
        System.out.println(JSONUtil.parse(parse).toJSONString(2));

    }

    public static void main(String[] args) {
        Assert.isTrue("" != null, "错误事件,抛弃");
    }
}
