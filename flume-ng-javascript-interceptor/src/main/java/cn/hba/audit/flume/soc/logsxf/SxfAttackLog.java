package cn.hba.audit.flume.soc.logsxf;

import cn.hba.audit.flume.util.DaTiUtil;
import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.core.date.DateUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * @author ikas
 */
public class SxfAttackLog {

    static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        disLog(syslog, obj);
        return obj;
    }

    /**
     * 处理日志信息
     *
     * @param syslog
     */
    private static void disLog(String syslog, JSONObject obj) {
        syslog = syslog.substring(syslog.indexOf("{") + 1, syslog.length() - 2).replaceAll("\"", "");
        JSONObject bodyJson = ParseMessageKv.parseMessage7(syslog);
        //必备字段
        obj.put("event_son_type", getEventSonType(bodyJson.getStr("event_type_sub")));
        obj.put("event_type", getEventType(bodyJson.getStr("event_type")));
        obj.put("event_time", DateUtil.parse(bodyJson.getStr("event_time")).toString(DaTiUtil.FORMAT));
        obj.put("log_type", "attack");
        obj.put("manufacturers_name", "深信服");
        obj.put("manufacturers_facility", "安全");
        obj.put("facility_type", "安全");
        obj.put("log_des", "深信服-安全-安全");

        obj.put("event_level", bodyJson.getStr("event_level"));
        obj.put("extra", bodyJson.getStr("extra"));
        obj.put("event_uuid", bodyJson.getStr("event_id"));
        obj.put("ip", bodyJson.getStr("ip"));
        obj.put("des", bodyJson.getStr("event_desc"));
        obj.put("facility_ip", bodyJson.getStr("device_ip"));
        obj.put("behaviour_type", bodyJson.getStr("behaviour_type"));
        obj.put("event_name", bodyJson.getStr("event_name"));
        obj.put("mac", bodyJson.getStr("mac"));
        obj.put("result", bodyJson.getStr("result"));
        obj.put("dest_port", bodyJson.getStr("dest_port"));
        obj.put("user_name", bodyJson.getStr("user_name"));
        obj.put("port", bodyJson.getStr("port"));
        obj.put("dest_ip", bodyJson.getStr("dest_ip"));
    }

    /**
     * 判断是否为攻击日志
     *
     * @param syslog 原始日志
     *
     *               <14>2019-07-03 14:32:34|!secevent|!192.3.222.68|!
     *               {"event_type_sub": "E02-3", "event_level": 1, "event_type": "E02", "event_time": "2019-07-03 09:34:33",
     *               "extra": {}, "event_id": "5d1c064fe138230e8677cd6a", "ip": "3.1.1.1", "event_desc": "主机对内网发起SSH扫描", "device_ip": "", "behaviour_type": 4, "event_name": "", "mac": "",
     *               "result": "主机很可能已被黑客控制，沦为跳板机，企图控制更多的内网其他主机；或为内网用户的恶意行为。如果是被黑客控制，则存在以下风险：\n1、造成机密信息被窃取，比如机密文件、关键资产的用户名和密码等；\n2、主机作为“肉鸡”攻击互联网上的其他单位，违反网络安全法，遭致网信办、网安等监管单位的通报处罚。",
     *               "dest_port": "", "user_name": "", "port": "", "dest_ip": ""}
     */
    static boolean isAttackLog(String syslog) {
        return StringUtil.containsAll(syslog, "event_type", "event_type_sub", "extra", "behaviour_type", "|!","mac");
    }

    /**
     * 获取事件类型
     */
    private static String getEventType(String eventType) {
        switch (eventType) {
            case "E01":
                return "harm_procedures";
            case "E02":
            case "E03":
                return "network_attack";
            case "E04":
            case "E05":
                return "abnormal";
            default:
                return "other";
        }
    }

    /**
     *
     * 获取事件子类型
     */
    private static String getEventSonType(String eventSonType) {
        switch (eventSonType) {
            case "E01-1":
                return "worm";
            case "E01-2":
                return "trojan_horse";
            case "E01-3":
                return "botnet";
            case "E01-4":
                return "viruses";
            case "E01-5":
                return "extortion";
            case "E01-6":
                return "mining";
            case "E02-2":
                return "brute_force";
            case "E02-4":
                return "phishing";
            case "E02-5":
                return "backdoor";
            case "E02-6":
                return "bug_exploits";
            case "E03-1":
                return "web_distort";
            case "E03-2":
                return "information_counterfeiting";
            case "E03-4":
                return "information_theft";
            case "E03-5":
                return "web_hanging_horse";
            case "E03-6":
                return "information_loss";
            case "E04-1":
                return "visit_malicious_links";
            case "E04-3":
                return "outgoing_attack";
            case "E04-4":
                return "covert_communication";
            case "E05-1":
                return "horizontal_attack";
            case "E05-2":
                return "illegal_access";
            case "E05-3":
                return "abnormal_behavior";
            default:
                return "other";

        }
    }
}
