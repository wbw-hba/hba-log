package cn.hba.audit.flume.soc.logsxf;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * @author ztf
 */
class SxfStrategyLog {
    static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        disLog(syslog, obj);
        return obj;
    }

    /**
     * 处理策略日志
     */
    private static void disLog(String syslog, JSONObject obj) {
        JSONObject bodyJson = ParseMessageKv.parseMessage1(syslog.split("fwlog:")[1].replaceAll(",", "").replaceAll("\\(null\\)", ""));
        obj.put("dest_ip", bodyJson.getStr("目的_IP"));
        obj.put("user_name", bodyJson.getStr("用户"));
        obj.put("ip", bodyJson.getStr("源_IP"));
        obj.put("rule_name", bodyJson.getStr("策略名称"));
        obj.put("dest_port", bodyJson.getStr("目的端口"));
        obj.put("apply_name", bodyJson.getStr("应用名称"));
        obj.put("port", bodyJson.getStr("源端口"));
        obj.put("conduct_operations", bodyJson.getStr("系统动作"));
        obj.put("apply_type", bodyJson.getStr("应用类型"));
        //必备字段
        obj.put("log_type", "strategy");
        obj.put("event_type", "authentication");
        obj.put("manufacturers_name", "深信服");
        obj.put("manufacturers_facility", "服务控制或应用控制");
        obj.put("facility_type", "服务控制或应用控制");
        obj.put("log_des", "深信服-服务控制或应用控制-认证");
    }

    /**
     * 判断是否为策略日志
     *
     * @param syslog 原始日志
     */
    static boolean isStrategyLog(String syslog) {
        return StringUtil.containsAll(syslog, "策略名称", "系统动作", "用户", "端口");
    }
}
