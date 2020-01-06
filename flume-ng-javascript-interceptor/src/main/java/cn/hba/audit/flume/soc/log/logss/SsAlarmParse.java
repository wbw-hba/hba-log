package cn.hba.audit.flume.soc.log.logss;

import cn.hutool.json.JSONObject;

/**
 * 山石告警
 *
 * @author lizhi
 * @date 2019/9/12 9:36
 */
class SsAlarmParse {


    static void alarmSyslog(String syslog, JSONObject obj) {
        String eventLogInfoId = obj.getStr("news_id");
        switch (eventLogInfoId) {
            case "424c0201":
                alarmSyslog1(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，对象使用率达到使用率%，高于阈值阀值%。");
                break;
            case "424c0202":
                alarmSyslog1(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，对象使用率达到使用率%，低于阈值阀值%。");
                break;
            case "424c0203":
                alarmSyslog1(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，对象使用率高于阈值阀值%持续 X 秒。");
                break;
            case "424c0204":
                alarmSyslog1(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，对象使用率低于阈值阀值%持续 X 秒。");
                break;
            case "424c0205":
                obj.put("message_content_explain", "级别：预警级别，对象利用率从旧状态状态转换到新状态状态。");
                break;
            case "424c0206":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的下行带宽使用率达到使用率%，高于阈值阀值%。");
                break;
            case "424c0207":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的下行带宽使用率达到使用率%，低于阈值阀值%。");
                break;
            case "424c0208":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的下行带宽使用率高于阈值阀值%持续 X 秒。");
                break;
            case "424c0209":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的下行带宽使用率低于阈值阀值%持续 X 秒。");
                break;
            case "424c020a":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的上行带宽使用率达到使用率%，高于阈值阀值%。");
                break;
            case "424c020b":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的上行带宽使用率达到使用率%，低于阈值阀值%。");
                break;
            case "424c020c":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的上行带宽使用率高于阈值阀值%持续 X 秒。");
                break;
            case "424c020d":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的上行带宽使用率低于阈值阀值%持续 X 秒。");
                break;
            case "424c020e":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的总带宽使用率达到使用率%，高于阈值阀值%。");
                break;
            case "424c020f":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的总带宽使用率达到使用率%，低于阈值阀值%。");
                break;
            case "424c0210":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的总带宽使用率高于阈值阀值%持续 X 秒。");
                break;
            case "424c0211":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的总带宽使用率低于阈值阀值%持续 X 秒。");
                break;
            case "424c0212":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，接口接口名称的带宽利用率从旧状态状态转换到新状态状态。");
                break;
            case "424c0213":
                alarmSyslog6(syslog, obj);
                obj.put("message_content_explain", "级别: 预警级别，IP IP 地址在SNAT 规则规则 ID 中的端口号端口利用率达到利用率%，高于阈值阀值%。");
                break;
            case "424c0214":
                alarmSyslog6(syslog, obj);
                obj.put("message_content_explain", "级别: 预警级别，SNAT 规则规则 ID 中的端口号端口利用率达到利用率%，高于阈值阀值%。");
                break;
            case "424c0215":
                alarmSyslog6(syslog, obj);
                obj.put("message_content_explain", "级别: 预警级别，IP IP 地址在SNAT 规则规则 ID 中的端口号端口利用率高于阈值阀值%持续 X 秒。");
                break;
            case "424c0216":
                alarmSyslog6(syslog, obj);
                obj.put("message_content_explain", "级别: 预警级别，SNAT 规则规则 ID 中的端口号端口利用率高于阈值阀值%持续 X 秒。");
                break;
            case "424c0217":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，SNAT 规则规则 ID  中的端口利用率从旧状态状态转换到新状态状态。");
                break;
            case "424c0218":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，IP ip-address in SNAT 规则规则 ID 中的端口利用率从旧状态状态转换到新状态状态。");
                break;
            case "424c0219":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，对象名称温度达到温度值℃，高于阈值温度值℃。");
                break;
            case "424c021a":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，对象名称温度高于阈值阀值℃持续 X 秒。");
                break;
            case "424c021b":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，对象名称温度从旧状态状态转换到新状态状态。");
                break;
            case "424c021c":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，网络节点节点名称的延时达到延迟时间 ms，高于阈值阀值 ms。");
                break;
            case "424c021d":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，网络节点节点名称的延迟高于阈值阀值 ms 持续 X 秒。");
                break;
            case "424c021e":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，网络节点节点名称的丢包率达到了丢包率%, 超过了预警阈值阀值%。");
                break;
            case "424c021f":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，网络节点节点名称的丢包率高于阈值阀值%持续 X 秒。");
                break;
            case "424c0220":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，网络节点节点名称从旧状态状态转换到新状态状态。");
                break;
            case "424c0221":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：服务服务节点延迟达到延迟时间 ms，高于预警阈值阀值 ms。");
                break;
            case "424c0222":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，服务服务节点延迟高于阈值阀值 ms 持续 X 秒。");
                break;
            case "424c0223":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，服务服务节点延迟从旧状态状态变到新状态状态。");
                break;
            case "424c0224":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的带宽达到带宽值 Kbps，高于阈值阀值 Kbps。");
                break;
            case "424c0225":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的带宽达到带宽值 Kbps，低于阈值阀值 Kbps。");
                break;
            case "424c0226":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的带宽高于阈值阀值 Kbps 持续 X 秒。");
                break;
            case "424c0227":
                alarmSyslog2(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的带宽低于阈值阀值 Kbps 持续 X 秒。");
                break;
            case "424c0228":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的新建连接数达到会话数个每秒，高于阈值阀值。");
                break;
            case "424c0229":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的新建连接数达到会话数个每秒，低于阈值阀值。");
                break;
            case "424c022a":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的新建连接数高于阈值阀值个每秒持续 X 秒。");
                break;
            case "424c022b":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的新建连接数低于阈值阀值个每秒持续 X 秒。");
                break;
            case "424022c":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的并发连接数达到会话数个，高于阈值阀值个。");
                break;
            case "424c022d":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的并发连接数达到会话数个，低于阈值阀值个。");
                break;
            case "424c022e":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的并发连接数高于阈值阀值个持续 X 秒。");
                break;
            case "424c022f":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的并发连接数低于阈值阀值个持续 X 秒。");
                break;
            case "424c0230":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的包转发率为转发率 pps，高于阈值阀值 pps。");
                break;
            case "424c0231":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的包转发率为转发率 pps，低于阈值阀值 pps。");
                break;
            case "424c0232":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的包转发率高于阈值阀值持续 X 秒。");
                break;
            case "424c0233":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，应用应用名称的包转发率低于阈值阀值持续 X 秒。");
                break;
            case "424c0234":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "错误：预警规则 id rule-ID 子规则 id subrule-ID 插入数据库失败。");
                break;
            case "424c0235":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "错误：插入网络服务节点 id ID 到数据库失败。");
                break;
            case "424c0236":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "错误：从数据库删除网络服务节点 id ID 失败。");
                break;
            case "424c0237":
                alarmSyslog7(syslog, obj);
                obj.put("message_content_explain", "错误：更新网络服务节点 id ID 到数据库失败。");
                break;
            case "424c0238":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，新建连接数达到会话数，高于阈值阀值。");
                break;
            case "424c0239":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，新建连接数达到会话数，低于阈值阀值。");
                break;
            case "424c023a":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，新建连接数高于阈值阀值持续 X 秒。");
                break;
            case "424c023b":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，新建连接数低于阈值阀值持续 X 秒。");
                break;
            case "424c023c":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，并发连接数达到会话数，高于阈值阀值。");
                break;
            case "424c023d":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，并发连接数达到会话数，低于阈值阀值。");
                break;
            case "424c023e":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，并发连接数高于阈值阀值持续 X 秒。");
                break;
            case "424c023f":
                alarmSyslog4(syslog, obj);
                obj.put("message_content_explain", "级别：预警级别，并发连接数低于阈值阀值持续 X 秒。");
                break;
            default:
                break;
        }
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, object utilization is value%, higher than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, object utilization is value%, lower than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, object utilization is higher than threshold threshold-value% for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, object utilization is lower than threshold threshold-value% for X seconds.
     */
    private static void alarmSyslog1(String syslog, JSONObject obj) {
        //解析预警等级
        String[] split = syslog.split("Level: ")[1].split(",");
        obj.put("alarm_level", split[0]);
        //解析使用对象
        String[] split2 = syslog.split(split[0].trim() + ",")[1].split(" utilization");
        obj.put("object", split2[0].trim());

        if (syslog.contains("seconds")) {
            //解析持续时长
            String[] split3 = syslog.split("for".trim())[1].split("seconds");
            obj.put("seconds", split3[0].trim());
        } else {
            //解析使用率
            String[] split4 = syslog.split("utilization is ")[1].split("%");
            obj.put("utilization", split4[0].trim());
        }
        //解析阈值
        String[] split5 = syslog.split("threshold ")[1].split("%");
        obj.put("threshold", split5[0].trim());
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, ingress bandwidth utilization of interface interface-name is value%, higher than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, ingress bandwidth utilization of interface interface-name is value%, lower than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, ingress bandwidth utilization of interface interface-name is higher than threshold threshold-value% for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, ingress bandwidth utilization of interface interface-name is lower than threshold threshold-value% for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, egress bandwidth utilization of interface interface-name is value%, higher than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, egress bandwidth utilization of interface interface-name is value%, lower than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, egress bandwidth utilization of interface interface-name is higher than threshold threshold-value% for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, egress bandwidth utilization of interface interface-name is lower than threshold threshold-value% for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, total bandwidth utilization of interface interface-name is value%, higher than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, total bandwidth utilization of interface interface-name is value%, lower than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, total bandwidth utilization of interface interface-name is higher than threshold threshold-value% for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, total bandwidth utilization of interface interface-name is lower than threshold threshold-value% for X seconds.
     */
    private static void alarmSyslog2(String syslog, JSONObject obj) {

        String[] split = syslog.split("Level: ")[1].split(",");
        obj.put("alarm_level", split[0].trim());

        String[] split2 = syslog.split(split[0].trim() + ",")[1].split(" utilization");
        obj.put("object", split2[0].trim());

        String[] split5 = syslog.split("interface ")[1].split("is");
        obj.put("interface_name", split5[0].trim());

        if (syslog.contains("seconds")) {
            String[] split3 = syslog.split(split5[0] + "is")[1].split("than");
            obj.put("utilization_status", split3[0].trim());

            String[] split6 = syslog.split("for")[1].split("seconds");
            obj.put("seconds", split6[0].trim());
        } else {
            String[] split3 = syslog.split(split5[0] + "is")[1].split("%");
            obj.put("utilization", split3[0]);
            String[] split6 = syslog.split(split3[0].trim() + "%,")[1].split("than");
            obj.put("utilization_status", split6[0].trim());
        }
        //解析阈值
        String[] split4 = syslog.split("threshold ")[1].split("%");
        obj.put("threshold", split4[0].trim());
    }


    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, bandwidth of application application-name is bandwidth-value Kbps, higher than threshold threshold-value Kbps.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, bandwidth of application application-name is bandwidth-value Kbps, lower than threshold threshold-value Kbps.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, bandwidth of application application-name is higher than threshold threshold-value Kbps for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, bandwidth of application application-name is lower than threshold threshold-value Kbps for X seconds.
     */
    private static void alarmSyslog3(String syslog, JSONObject obj) {
        String[] split = syslog.split("Level: ")[1].split(",");
        obj.put("alarm_level", split[0].trim());

        String[] split2 = syslog.split(split[0].trim() + ",")[1].split(" of application");
        obj.put("object", split2[0]);

        String[] split5 = syslog.split("application ")[1].split("is");
        obj.put("object", split5[0].trim());

        if (!syslog.contains("seconds")) {
            String[] split3 = syslog.split(split5[0] + "is")[1].split("Kbps");
            obj.put("bandwidth_value", split3[0].trim());

            String[] split4 = syslog.split("Kbps, ")[1].split("than");
            obj.put("utilization_status", split4[0].trim());

            String[] split6 = syslog.split("threshold ")[1].split("Kbps");
            obj.put("threshold", split6[0].trim());
        } else {
            lastSeconds(syslog, obj, syslog.split(split5[0] + "is"), "Kbps");
        }

    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, number of new sessions of application application-name is session-number, higher than threshold threshold-value.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, number of new sessions of application application-name is session-number, lower than threshold threshold-value.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, number of new sessions of application application-name is higher than threshold threshold-value for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, number of new sessions of application application-name is lower than threshold threshold-value for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, number of concurrent sessions of application application-name is session-number, higher than threshold threshold-value.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, number	of concurrent sessions of application application-name is session-number, lower than threshold threshold-value.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, number	of concurrent sessions of application application-name is higher than threshold threshold-value for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, number	of concurrent sessions of application application-name is lower than threshold threshold-value for X seconds.
     */
    private static void alarmSyslog4(String syslog, JSONObject obj) {
        String[] split = syslog.split("Level: ")[1].split(",");
        obj.put("alarm_level", split[0].trim());

        String[] split2 = syslog.split(split[0].trim() + ",")[1].split(" of application");
        obj.put("object", split2[0].trim());

        String[] split5 = syslog.split("application ")[1].split("is");
        obj.put("application_name", split5[0].trim());

        if (!syslog.contains("seconds")) {
            String[] split3 = syslog.split(split5[0] + "is")[1].split(",");
            obj.put("session_number", split3[0].trim());

            String[] split4 = syslog.split(split3[0] + ",")[1].split("than");
            obj.put("utilization_status", split4[0].trim());

            String[] split6 = syslog.split("threshold ")[1].split("\\.");
            obj.put("threshold", split6[0].trim());
        } else {
            lastSeconds(syslog, obj, syslog.split(split5[0] + "is"), "for");
        }

    }

    private static void lastSeconds(String syslog, JSONObject obj, String[] split7, String s) {
        String[] split3 = split7[1].split("than");
        obj.put("utilization_status", split3[0].trim());

        String[] split4 = syslog.split("threshold ")[1].split(s);
        obj.put("threshold", split4[0].trim());

        String[] split6 = syslog.split("for ")[1].split("seconds");
        obj.put("seconds", split6[0].trim());
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: number of new sessions is session-number, higher than threshold threshold-value.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: number of new sessions is session-number, lower than threshold threshold-value.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: number of new sessions is higher than threshold threshold-value for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: number of new sessions is lower than threshold threshold-value for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: number of concurrent sessions is session-number, higher than threshold threshold-value.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: number of concurrent sessions s session-number, lower than threshold threshold-value.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: number of concurrent sessions is higher than threshold threshold-value for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: number of concurrent sessions is lower than threshold threshold-value for X seconds.
     */
    private static void alarmSyslog5(String syslog, JSONObject obj) {

        String[] split = syslog.split(": ")[1].split("is");
        obj.put("object", split[0].trim());

        if (!syslog.contains("seconds")) {
            String[] split2 = syslog.split(split[0] + "is")[1].split(",");
            obj.put("session_number", split2[0].trim());

            String[] split5 = syslog.split(split2[0].trim() + ", ")[1].split("than");
            obj.put("utilization_status", split5[0].trim());

            String[] split6 = syslog.split("threshold ")[1].split("\\.");
            obj.put("threshold", split6[0].trim());
        } else {
            lastSeconds(syslog, obj, syslog.split(split[0] + "is"), "for");
        }

    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, IP ip-address in SNAT rule ID port-number port utilization is utilization-value%, higher than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, in SNAT rule ID port-number port utilization is utilization-value%, higher than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, IP ip-address in SNAT rule ID port-number port utilization is higher than threshold threshold-value% for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, in SNAT rule ID port-number port utilization is higher than threshold threshold-value% for X seconds.
     */
    private static void alarmSyslog6(String syslog, JSONObject obj) {
        String[] split = syslog.split("Level: ")[1].split(",");
        obj.put("alarm_level", split[0].trim());
        if (syslog.contains("IP")) {
            String[] split2 = syslog.split(split[0] + ", IP")[1].split("in");
            obj.put("source_ip", split2[0].trim());
        }
        String[] split5 = syslog.split("SNAT rule ")[1].split(" ");
        obj.put("SNAT_rule", split5[0].trim());
        String[] split6 = syslog.split(split5[0] + " ")[1].split(" ");
        obj.put("SNAT_rule_port", split6[0].trim());

        if (!syslog.contains("seconds")) {
            String[] split7 = syslog.split("utilization is ")[1].split("%");
            obj.put("utilization", split7[0].trim());

            String[] split8 = syslog.split(split7[0].trim() + "%,")[1].split("than");
            obj.put("utilization_status", split8[0].trim());

            String[] split9 = syslog.split("threshold ")[1].split("%");
            obj.put("threshold", split9[0].trim());
        } else {
            String[] split7 = syslog.split("utilization is ")[1].split("than");
            obj.put("utilization_status", split7[0].trim());

            String[] split9 = syslog.split("threshold ")[1].split("%");
            obj.put("threshold", split9[0].trim());

            String[] split8 = syslog.split("for")[1].split("seconds");
            obj.put("seconds", split8[0].trim());
        }
    }

    /**
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, object transformed from old-status status to new-status status.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, bandwidth utilization of interface interface-name transformed from old-status status to new-status status.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, port utilization of SNAT rule ID transformed from old-status status to new-status status.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, IP ip-address in of SNAT rule ID transformed from old-status status to new-status status.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, object temperature is tem-value degrees celsius, higher than threshold threshold-value degrees celsius.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, object temperature is higher than threshold threshold-value degrees celsius for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, object temperature transformed from old-status status to new-status status.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, delay of network node node-name is delay-time ms, higher than threshold threshold-value ms.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, delay of network node node-name is higher than threshold threshold-value ms for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, loss rate of network node node-name is loss-rate%, higher than threshold threshold-value%.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, loss rate of network node node-name is higher than threshold threshold-value% for X seconds.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, network node node-name transformed from old-status state to new-status state.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, delay of service node service-node is delay-time ms, higher than threshold threshold-value ms.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: delay of	service	node service-node is higher than threshold threshold-value ms for X seconds
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: Level: level, delay of service node service-node transformed from old-status state to new-status state.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: ERROR: Alarm-rule id rule-ID subrule id subrule-ID insert into mysql failed.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: ERROR: insert service network node id ID to mysql failed.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: ERROR: del service network node id ID from mysql failed.
     * <186>Jul 9 17:24:24 1304415172004234(root) 44040204 Event@SECURITY: ERROR: update service network node id ID to mysql failed.
     */
    private static void alarmSyslog7(String syslog, JSONObject obj) {
        String[] split = syslog.split("Level: ")[1].split(",");
        obj.put("alarm_level", split[0].trim());
    }


}
