package cn.hba.audit.flume.soc.log.logapt;

import cn.hba.audit.flume.soc.exception.abandon.AbandonLog;
import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

import java.util.ArrayList;


/**
 * @author ikas
 */
class AptParse {
    static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        int a = syslog.indexOf("\t");
        String str = syslog.substring(a + 1).replaceAll("null", "");
        String[] logSplit = str.split("\t");
        if (logSplit.length == 35 && StrUtil.isNotEmpty(logSplit[7])) {
            disBody(logSplit, obj);
            return obj;
        } else {
            // 该日志无事件类别，主动丢弃
            return AbandonLog.of("apt");
        }
    }

    /**
     * 数据库日志判断
     *
     * @param syslog 日志
     * @return flag
     */
//    private static boolean isSqlLog(String syslog) {
//        syslog.split("")
////        if (s)
//    }

    private static void disBody(String[] logSplit, JSONObject obj) {
        ArrayList<String> param = CollUtil.newArrayList(
                "timestamp", "facility_hostname", "sensor_ip", "event_source", "log_id", "inter", "threat_id", "classtype",
                "threat_type", "threat_subtype", "ip", "port", "ip_service", "dest_ip", "dest_port", "dest_ip_service", "proto",
                "app_protocol", "kill_chain", "payload", "resp_data", "severity", "reliability", "fam", "object_id", "message_content",
                "message_content_explain", "src_addr_state", "src_addr_city", "src_addr_geoloc", "src_addr_state_code",
                "dst_addr_state", "dst_addr_city", "dst_addr_geoloc", "dst_addr_state_code");
        for (int i = 0; i < logSplit.length; i++) {
            obj.put(param.get(i), logSplit[i]);
        }

        obj.put("kill_chain", killChain((String) obj.get("kill_chain")));
        obj.put("severity", severity((String) obj.get("severity")));

        //必备字段
        if ("web_attack".equals(classType(obj.getStr("classtype")))) {
            obj.put("attack_type", threatType((String) obj.get("threat_type")));
            obj.remove("threat_type");
            obj.put("log_type", "attack");
            obj.put("event_type", "apt");
            obj.put("event_son_type", "apt");
            obj.put("log_des", "apt-攻击-apt");
        } else {
            obj.put("log_type", "menace");
            obj.put("event_type", classType(obj.getStr("classtype")));
            obj.put("log_des", "apt-apt-安全事件");
            obj.put("threat_type", threatType((String) obj.get("threat_type")));
        }
        obj.put("manufacturers_name", "apt");
        obj.put("manufacturers_facility", "apt");
        obj.put("facility_type", "安全事件");

        //删除与说明文档重复的属性
        obj.remove("sensor_ip");
        obj.remove("classtype");
    }


    /**
     * 威胁类型
     *
     * @param threatTypeName 类型名称
     */
    private static String threatType(String threatTypeName) {
        switch (threatTypeName) {
            case "weird-dns-behavior":
                return "dns异常行为";
            case "bad-unknown":
                return "潜在恶意流量";
            case "web-attack":
                return "Web应用攻击";
            case "web-overflow-attacks":
                return "Web溢出攻击";
            case "address-scan":
                return "地址扫描";
            case "weak-password":
                return "弱口令/弱密码";
            default:
                return "other";
        }
    }

    /**
     * 事件攻击链位置
     */
    private static String killChain(String killChainName) {
        switch (killChainName) {
            case "security-defect":
                return "安全缺陷";
            case "scan-detect":
                return "扫描探测";
            case "attempt-attack":
                return "尝试攻击";
            case "infected":
                return "初步感染";
            case "malware-download":
                return "木马下载";
            case "remote-control":
                return "远程控制";
            case "internal-penertration":
                return "横向渗透";
            case "actions-objectives":
                return "行动收割";
            default:
                return "";
        }
    }

    /**
     * 威胁严重性
     */
    private static String severity(String severityName) {
        switch (severityName) {
            case "1":
                return "信息";
            case "2":
                return "轻微";
            case "3":
                return "一般";
            case "4":
                return "重要";
            case "5":
                return "严重";
            default:
                return "信息";
        }
    }

    /**
     * 威胁大类
     */
    private static String classType(String classTypeName) {
        switch (classTypeName) {
            case "weird-behavior":
                return "weird_behavior";
            case "bad-unknown":
                return "bad_unknown";
            case "scan":
                return "scan";
            case "policy-violation":
                return "policy_violation";
            case "web-attack":
                return "web_attack";
            default:
                return "other";
        }
    }

}
