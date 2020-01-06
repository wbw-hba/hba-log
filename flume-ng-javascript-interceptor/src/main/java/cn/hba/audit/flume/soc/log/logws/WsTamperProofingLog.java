package cn.hba.audit.flume.soc.log.logws;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 防篡改日志
 *
 * @author wbw
 * @date 2019/11/29 9:39
 */
public class WsTamperProofingLog {

    /**
     * 是否为防篡改日志
     */
    static boolean isTamperProofingLog(String syslog) {
        return StringUtil.containsAll(syslog, "-:", "devicename=", "process=", "attack=", "file=");
    }

    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        disLog(syslog, obj);
        // 必备字段
        obj.put("log_type", "attack");
        obj.put("event_type", "waf");
        obj.put("event_son_type", "tamper_proofing");
        obj.put("manufacturers_name", "网神");
        obj.put("manufacturers_facility", "WEB");
        obj.put("facility_type", "系统防护");
        obj.put("log_des", "网神 - WAF - 防篡改日志");
        return obj;
    }

    /**
     * 日志格式：
     * 2010-04-23 00:33:33-: webname="jason-linux" devicename="Jason" process="N/A" attack="del" file="wjc.txt" mgt_ip=2.2.2.2
     */
    private static void disLog(String syslog, JSONObject obj) {
        String body = syslog.split("-:")[1];
        if (body.contains("mgt_ip=")) {
            String[] split = body.split("mgt_ip=");
            obj.put("mgt_ip", StrUtil.trim(split[1]));
            body = split[0];
        }
        JSONObject bodyJson = ParseMessageKv.parseMessage6(body);
        obj.put("facility_hostname", bodyJson.getStr("devicename"));
        obj.put("process", bodyJson.getStr("process"));
        obj.put("conduct_operations", bodyJson.getStr("attack"));
        obj.put("file_path", bodyJson.getStr("file"));
        obj.put("protect_target", bodyJson.getStr("webname"));
    }
}
