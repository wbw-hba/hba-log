package cn.hba.audit.flume.soc.log.logahjh;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 数据库防火墙解析
 *
 * @author wbw
 * @date 2020/1/7 16:24
 */
public class DbFwLog {

    /**
     * 日志
     * <8>Dec 22 01:30:25 DBF35M DBFW: CEF:192.168.81.209:514|发生时间:2019-12-22 01:30:15|服务器IP:192.168.101.13|服务器端口:3306|
     * 数据库实例名:mysql|数据库版本:MySQL 5.700|客户端IP:192.168.101.1|客户端端口:35640|客户端MAC:000000000000|数据库用户:ELSSP|
     * 操作系统用户:无信息|风险类型[风险级别]:操作违规[高] |引擎动作:放行|规则名称:高危操作_yw|SQL报文:DROP TABLE ELSSP.CATALOG_TO_DEL
     *
     * @param body 主体
     * @return obj
     */
    static Object parse(String body) {
        JSONObject object = JSONUtil.parseObj(body);
        String syslog = object.getStr("syslog");
        // 公共处理
        disPucHead(syslog, object);
        // 主体处理
        disLogBody(syslog, object);
        return object;
    }

    /**
     * 处理主体
     *
     * @param syslog 日志
     * @param obj    对象
     */
    private static void disLogBody(String syslog, JSONObject obj) {
        String[] logs = syslog.substring(syslog.indexOf(": ") + 1).trim().split("\\|");
        JSONObject objMess = JSONUtil.createObj();
        for (String log : logs) {
            log = log.trim();
            objMess.put(log.substring(0, log.indexOf(":")), log.substring(log.indexOf(":") + 1));
        }
        obj.put("type",objMess.getStr("风险类型[风险级别]"));
        obj.put("cef",objMess.getStr("CEF"));
        obj.put("rule_name",objMess.getStr("规则名称"));
        obj.put("server_port",objMess.getStr("服务器端口"));
        obj.put("client_port",objMess.getStr("客户端端口"));
        obj.put("db_ver",objMess.getStr("数据库版本"));
        obj.put("user_name",objMess.getStr("数据库用户"));
        obj.put("conduct_operations",objMess.getStr("引擎动作"));
        obj.put("db_example_name",objMess.getStr("数据库实例名"));
        obj.put("event_time",objMess.getStr("发生时间"));
        obj.put("sql_mess",objMess.getStr("SQL报文"));
        obj.put("client_ip",objMess.getStr("客户端IP"));
        obj.put("opt_sys_user",objMess.getStr("操作系统用户"));
        obj.put("server_ip",objMess.getStr("服务器IP"));
    }

    /**
     * 公共处理
     *
     * @param syslog log
     */
    private static void disPucHead(String syslog, JSONObject obj) {
        String[] head = syslog.substring(0, syslog.indexOf(": ")).split(" ");
        obj.put("facility_hostname", head[head.length - 2]);
        obj.put("module_name", head[head.length - 1]);

        obj.put("log_type", "network");
        obj.put("event_type", "database");
        obj.put("manufacturers_name", "安和金华");
        obj.put("manufacturers_facility", "防火墙");
        obj.put("facility_type", "数据库");
        obj.put("log_des", "安和金华 - 数据库- 防火墙");

    }

    /**
     * 是否为数据防火墙日志
     *
     * @param syslog 日志
     * @return flag
     */
    static boolean isDbFwLog(String syslog) {
        if (syslog.split("\\|").length < 6) {
            return false;
        }
        return StringUtil.containsAll(syslog, "发生时间", "服务器IP", "服务器端口", "数据库实例名");
    }
}
