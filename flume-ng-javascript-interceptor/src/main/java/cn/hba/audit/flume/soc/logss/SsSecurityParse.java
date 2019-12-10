package cn.hba.audit.flume.soc.logss;

import cn.hutool.json.JSONObject;

/**
 * 山石安全
 *
 * @author lizhi
 * @date 2019/9/12 9:40
 */
class SsSecurityParse {

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: file-name!error-string.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Failed to allocate memory for error string, the configuration can not take effect.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: From source-ip：source-port(src-interface-name) to destination-ip:destination-port(dst-interface-name), threat name: threat name, threat type: threat type, threat subtype: threat subtype, App/Protocol: App/Protocol, action: action, defender: defender severity: severity, zone zone-name: alarm
     */
    static void securitySyslog(String syslog, JSONObject obj) {
        String eventLogInfoId = obj.getStr("news_id");
        switch (eventLogInfoId) {
            case "460c5401":
                securitySyslog1(syslog, obj);
                obj.put("message_content_explain", "攻击类型：丢弃！zone-name：：接口名称源IP->目的IP。");
                break;
            case "460c5402":
                securitySyslog1(syslog, obj);
                obj.put("message_content_explain", "攻击类型：警告！zone-name：：接口名称源IP->目的IP。");
                break;
            case "460c5403":
                securitySyslog2(syslog, obj);
                obj.put("message_content_explain", "攻击类型：丢弃！zone-name：：接口名称源IP->目的IP。发生了N次（在前X秒内）。");
                break;
            case "460c5404":
                securitySyslog2(syslog, obj);
                obj.put("message_content_explain", "攻击类型：警告！zone-name：：接口名称源IP->目的IP。发生了N次（在前X秒内）。");
                break;
            case "460c5405":
                obj.put("message_content_explain", "文件名称！错误信息。");
                break;
            case "460c5406":
                securitySyslog3(syslog, obj);
                obj.put("message_content_explain", "攻击类型：丢弃！目的地址目的IP。发生了N次（在前X秒内）。");
                break;
            case "460c5407":
                securitySyslog3(syslog, obj);
                obj.put("message_content_explain", "攻击类型：警告！目的地址目的IP。发生了N次（在前X秒内）。");
                break;
            case "460c5408":
                securitySyslog3(syslog, obj);
                obj.put("message_content_explain", "攻击类型：丢弃！源地址源IP。发生了N次（在前X秒内）。");
                break;
            case "460c5409":
                securitySyslog3(syslog, obj);
                obj.put("message_content_explain", "攻击类型：警告！源地址源IP。发生了N次（在前X秒内）。");
                break;
            case "460c540a":
                securitySyslog4(syslog, obj);
                obj.put("message_content_explain", "攻击类型：丢弃！zone-name：：接口名称源IP->目的IP:端口号。");
                break;
            case "460c540b":
                securitySyslog4(syslog, obj);
                obj.put("message_content_explain", "攻击类型：警告！zone-name：：接口名称源IP->目的IP:端口号。");
                break;
            case "460c540c":
                securitySyslog4(syslog, obj);
                obj.put("message_content_explain", "攻击类型：丢弃！zone-name：：接口名称源IP->目的IP:端口号。发生了N次（在前X秒内）。");
                break;
            case "460c540d":
                securitySyslog4(syslog, obj);
                obj.put("message_content_explain", "攻击类型：警告！zone-name：：接口名称源IP->目的IP:端口号。发生了N次（在前X秒内）。");
                break;
            case "460c540e":
                securitySyslog5(syslog, obj);
                obj.put("message_content_explain", "攻击类型：丢弃！目的地址目的IP:端口号。发生了N次（在前X秒内）。");
                break;
            case "460c540f":
                securitySyslog5(syslog, obj);
                obj.put("message_content_explain", "攻击类型：警告！目的地址目的IP:端口号。发生了N次（在前X秒内）。");
                break;
            case "460c0410":
                obj.put("message_content_explain", "为错误信息分配内存失败，配置无法生效。");
                break;
            case "460c9412":
                securitySyslog6(syslog, obj);
                obj.put("message_content_explain", "从源IP地址：源接口（源接口名称）到目的IP地址：目的接口(目的接口名称)，威胁名称：威胁名称，威胁类型：威胁类型，威胁子类型：威胁子类型，应用/协议：应用/协议，响应行为：响应行为，检测引擎：检测引擎，威胁等级：威胁等级，安全域安全域名称：告警信息。 ");
                break;
            case "460c9413":
                securitySyslog6(syslog, obj);
                obj.put("message_content_explain", "从源IP地址：源接口（源接口名称）到目的IP地址：目的接口(目的接口名称)，威胁名称：威胁名称，威胁类型：威胁类型，威胁子类型：威胁子类型，应用/协议：应用/协议，响应行为：响应行为，检测引擎：检测引擎，威胁等级：威胁等级，安全域安全域名称：告警信息，发生了N次攻击（在前X秒内）。");
                break;
            default:
                break;
        }
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: attack-type:DROP! zone-name::interface-name source-ip->destination-ip.
     */
    private static void securitySyslog1(String syslog, JSONObject obj) {
        //解析攻击类型
        String[] split = syslog.split("attack-type:")[1].split("!");
        obj.put("attack_type", split[0]);
        //解析区域
        String[] split1 = syslog.split("! ")[1].split("::");
        obj.put("slot", split1[0]);
        //解析接口名称
        String[] split2 = syslog.split(split1[0].trim() + "::")[1].split(" ");
        obj.put("in_ifname", split2[0]);
        //解析源IP
        String[] split3 = syslog.split(split2[0].trim() + " ")[1].split("->");
        obj.put("source_ip", split3[0].trim());
        //解析目的IP
        String[] split4 = syslog.split(split3[0].trim() + "->")[1].split("\\.");
        obj.put("destination_ip", split4[0].trim());
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: attack-type:DROP! zone-name::interface-name source-ip->destination-ip. Occurred attack-times(N) times in the last seconds(X) seconds.
     */
    private static void securitySyslog2(String syslog, JSONObject obj) {
        securitySyslog1(syslog, obj);
        String[] split5 = syslog.split("attack-times\\(")[1].split("\\)");
        obj.put("attack_times", split5[0]);

        String[] split6 = syslog.split("seconds\\(")[1].split("\\)");
        obj.put("attack_seconds", split6[0].trim());
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: attack-type:DROP! Destination IP destination-ip. Occurred attack-times(N) times in the last seconds(X) seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: attack-type:DROP! Source IP source-ip. Occurred attack-times(N) times in the last seconds(X) seconds.
     */
    private static void securitySyslog3(String syslog, JSONObject obj) {
        //解析攻击类型
        String[] split = syslog.split("attack-type:")[1].split("\\!");
        obj.put("attack_type", split[0].trim());
        //解析目的ip或者源ip
        if (syslog.contains("Destination IP")) {
            String[] split2 = syslog.split("Destination IP ")[1].split("\\.");
            obj.put("destination_ip", split2[0].trim());
        } else if (syslog.contains("Source IP")) {
            String[] split2 = syslog.split("Source IP ")[1].split("\\.");
            obj.put("source_ip", split2[0].trim());
        }
        //解析攻击次数
        String[] split3 = syslog.split("attack-times\\(")[1].split("\\)");
        obj.put("attack_times", split3[0]);
        //解析攻击时长
        String[] split4 = syslog.split("seconds\\(")[1].split("\\)");
        obj.put("attack_seconds", split4[0]);
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: attack-type:DROP! zone-name::interface-name source-ip->destination-ip:port-number.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: attack-type:DROP! zone-name::interface-name source-ip->destination-ip:port-number. Occurred attack-times(N) times in the last seconds(X) seconds.
     */
    private static void securitySyslog4(String syslog, JSONObject obj) {

        String[] split = syslog.split("attack-type:")[1].split("\\!");
        obj.put("attack_type", split[0].trim());

        String[] split1 = syslog.split("! ")[1].split("::");
        obj.put("slot", split1[0].trim());

        String[] split2 = syslog.split(split1[0].trim() + "::")[1].split(" ");
        obj.put("in_ifname", split2[0].trim());

        String[] split3 = syslog.split(split2[0].trim() + " ")[1].split("->");
        obj.put("source_ip", split3[0].trim());

        String[] split4 = syslog.split(split3[0].trim() + "->")[1].split("\\:");
        obj.put("destination_ip", split4[0].trim());

        String[] split7 = syslog.split(split4[0].trim() + ":")[1].split("\\.");
        obj.put("destination_port", split7[0].trim());

        if (syslog.contains("attack-times")) {
            String[] split5 = syslog.split("attack-times\\(")[1].split("\\)");
            obj.put("attack_times", split5[0].trim());

            String[] split6 = syslog.split("seconds\\(")[1].split("\\)");
            obj.put("attack_seconds", split6[0].trim());
        }
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: attack-type:DROP! Destination IP destination-ip:port-number. Occurred attack-times(N) times in the last seconds(X) seconds.
     */
    private static void securitySyslog5(String syslog, JSONObject obj) {

        String[] split = syslog.split("attack-type:")[1].split("\\!");
        obj.put("attack_type", split[0].trim());

        String[] split2 = syslog.split("Destination IP ")[1].split("\\:");
        obj.put("destination_ip", split2[0].trim());

        String[] split5 = syslog.split(split2[0].trim() + ":")[1].split("\\.");
        obj.put("destination_port", split5[0].trim());

        String[] split3 = syslog.split("attack-times\\(")[1].split("\\)");
        obj.put("attack_times", split3[0].trim());

        String[] split4 = syslog.split("seconds\\(")[1].split("\\)");
        obj.put("attack_seconds", split4[0].trim());
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: From source-ip：source-port(src-interface-name) to destination-ip:destination-port(dst-interface-name), threat name: threat name, threat type: threat type, threat subtype: threat subtype, App/Protocol: App/Protocol, action: action, defender: defender severity: severity, zone zone-name: alarm
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: From source-ip：source-port(src-interface-name) to destination-ip:destination-port(dst-interface-name), threat name: threat name, threat type: threat type, threat subtype: threat subtype, App/Protocol: App/Protocol, action: action, defender: defender severity: severity, zone zone-name: alarm, occurred attack-times（N）times in the last(X)seconds
     */
    private static void securitySyslog6(String syslog, JSONObject obj) {

        String[] split = syslog.split("From ")[1].split("\\:");
        obj.put("source_ip", split[0].trim());

        String[] split2 = syslog.split(split[0].trim() + ":")[1].split("\\(");
        obj.put("source_port", split2[0].trim());

        String[] split5 = syslog.split(split2[0].trim() + "\\(")[1].split("\\)");
        obj.put("out_ifname", split5[0].trim());

        String[] split3 = syslog.split("to".trim())[1].split("\\:");
        obj.put("destination_ip", split3[0].trim());

        String[] split4 = syslog.split(split3[0].trim() + ":")[1].split("\\(");
        obj.put("destination_port", split3[0].trim());
        System.out.println(split4[0].trim());

        String[] split6 = syslog.split(split4[0].trim() + "\\(")[1].split("\\)");
        obj.put("in_ifname", split6[0].trim());

        String[] split7 = syslog.split("threat name:")[1].split(",");
        obj.put("threat_name", split7[0].trim());
        System.out.println(split7[0].trim());

        String[] split8 = syslog.split("threat type:")[1].split(",");
        obj.put("threat_type", split8[0].trim());
        System.out.println(split8[0].trim());

        String[] split9 = syslog.split("threat subtype:")[1].split(",");
        obj.put("threat_subtype", split9[0].trim());

        String[] split10 = syslog.split("App/Protocol:")[1].split(",");
        obj.put("app_protocol", split10[0].trim());

        String[] split11 = syslog.split("action:".trim())[1].split(",");
        obj.put("action", split11[0].trim());

        String[] split12 = syslog.split("defender:")[1].split("severity");
        obj.put("defender", split12[0].trim());

        String[] split13 = syslog.split("severity:")[1].split(",");
        obj.put("severity", split13[0].trim());

        String[] split14 = syslog.split("zone ")[1].split("\\:");
        obj.put("zone_name", split14[0].trim());
        System.out.println(split14[0].trim());

        String[] split17 = syslog.split(split14[0].trim() + ":")[1].split(",");
        obj.put("alarm", split17[0].trim());
        if (syslog.contains("attack-times")) {
            String[] split15 = syslog.split("attack-times\\(")[1].split("\\)");
            obj.put("attack_times", split15[0].trim());

            String[] split16 = syslog.split("last\\(")[1].split("\\)");
            obj.put("attack_seconds", split16[0].trim());
        }
    }

}
