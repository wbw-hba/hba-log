package cn.hba.audit.flume.soc.log.logsxf;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * @author ztf
 */
class SxfFlowLog {

    static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        disLog(syslog, obj);
        return obj;
    }

    /**
     * 处理流量日志
     */
    private static void disLog(String syslog, JSONObject obj) {
        JSONObject bodyJson = ParseMessageKv.parseMessage1(syslog.split("fwlog:")[1].replaceAll(",", ""));
        obj.put("facility_hostname", bodyJson.getStr("用户名/主机"));
        obj.put("up_flow", bodyJson.getStr("上行流量(_KB_)"));
        obj.put("down_flow", bodyJson.getStr("下行流量(_KB_)"));
        obj.put("total_flow", bodyJson.getStr("总流量(KB)"));
        obj.put("apply_type", bodyJson.getStr("应用类型"));
        //必备字段
        obj.put("log_type", "flow");
        obj.put("event_type", "flow");
        obj.put("manufacturers_name", "深信服");
        obj.put("manufacturers_facility", "流量审计");
        obj.put("facility_type", "流量审计");
        obj.put("log_des", "深信服-流量审计-流量");
    }

    /**
     * 判断是否为流量日志
     *
     * @param syslog 原始日志
     */
    static boolean isFlowLog(String syslog) {
        return StringUtil.containsAll(syslog, "流量审计", "上行流量", "下行流量", "KB");
    }

}
