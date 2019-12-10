package cn.hba.audit.flume.soc.logws;

import cn.hba.audit.flume.util.AttackUtil;
import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 网神 doss 攻击
 *
 * @author wbw
 * @date 2019/11/29 10:03
 */
public class WsDdosLog {

    /**
     * 是否为 ddos 日志
     */
    static boolean isDdosLog(String syslog) {
        return StringUtil.containsAll(syslog, "devicename=", "sip=", "sport=", "dport=", "ipproto=", "attack=");
    }

    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        disLog(syslog, obj);
        // 必备字段
        obj.put("log_type", "attack");
        obj.put("event_type", "ddos");
        AttackUtil.eventSonType(obj.getStr("protocol_type"), obj);
        obj.put("manufacturers_name", "网神");
        obj.put("manufacturers_facility", "WEB");
        obj.put("facility_type", "系统防护");
        obj.put("log_des", "网神 - WAF - ddos攻击日志");
        return obj;
    }

    /**
     * 日志格式:
     * 2010-04-23 00:33:33-:devicename=jason-linux sip=1.2.3.4 sport=56 dip=1.2.3.5 dport=78 ipproto=UDP attack=UDP Syn Flood +
     */
    private static void disLog(String syslog, JSONObject obj) {
        syslog = StrUtil.trim(syslog);
        if (syslog.endsWith("+")) {
            syslog = StrUtil.strip(syslog, "+").trim();
        }
        JSONObject bodyJson = ParseMessageKv.parseMessage6(syslog.split("-:")[1]);
        obj.put("facility_hostname", bodyJson.getStr("devicename"));
        obj.put("ip", bodyJson.getStr("sip"));
        obj.put("port", bodyJson.getStr("sport"));
        obj.put("dest_ip", bodyJson.getStr("dip"));
        obj.put("dest_port", bodyJson.getStr("dport"));
        obj.put("protocol_type", bodyJson.getStr("ipproto"));
        obj.put("attack_text", bodyJson.getStr("attack"));
    }
}
