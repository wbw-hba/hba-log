package cn.hba.audit.flume.soc.logsxf;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;

/**
 * 系统程序
 *
 * @author wbw
 * @date 2019-12-05 20:25
 */
class SxfProcedureLog {

    /**
     * 是否为程序日志
     *
     * @param syslog 原始日志
     * @return flag
     */
    static boolean isProcedureLog(String syslog) {
        return StringUtil.containsAll(syslog, " 日志类型=", "程序路径=");
    }

    /**
     * 格式：
     * <158>Dec  5 03:01:09 b03-security-serverblade 日志类型=未知程序告警;平台ip=192.168.92.42;程序路径=/usr/local/hb/hbla;
     * 程序大小=969048;Hash值=-160840593;风险级别=6;上报日期=1575486014
     *
     * @param syslog 原始格式
     * @param object 结果
     * @return object
     */
    static Object parseProcedureLog(String syslog, JSONObject object) {
        String[] log = syslog.split(" 日志类型=");
        String[] hostname = log[0].split(" ");
        object.put("facility_hostname", hostname[hostname.length - 1]);
        JSONObject logJson = ParseMessageKv.parseMessage3("日志类型=" + log[1]);
        object.put("event_details", logJson.getStr("日志类型"));
        object.put("server_ip", logJson.getStr("平台ip"));
        object.put("course_path", logJson.getStr("程序路径"));
        object.put("size", logJson.getStr("程序大小"));
        object.put("hash_value", logJson.getStr("Hash值"));
        object.put("risk_level", logJson.getStr("风险级别"));
        object.put("an_date", logJson.getStr("上报日期"));
        // 必备字段
        object.put("event_type", "procedure");
        object.put("manufacturers_name", "深信服");
        object.put("manufacturers_facility", "系统");
        object.put("facility_type", "系统");
        object.put("log_des", "深信服-系统-程序运行");
        return object;
    }
}
