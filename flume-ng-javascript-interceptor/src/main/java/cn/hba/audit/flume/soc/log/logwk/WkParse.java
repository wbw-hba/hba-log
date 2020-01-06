package cn.hba.audit.flume.soc.log.logwk;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 网康 防火墙
 *
 * @author wbw
 * @date 2019/10/21 10:41
 */
public class WkParse {

    static JSONObject parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        obj.put("manufacturers_name", "wk");
        obj.put("log_type", "fw");
        obj.put("event_type", "system");
        obj.put("log_des", "网康 - 系统");
        if (isSasOptLog(syslog)) {
            disSasOpt(syslog, obj);
        } else if (isSasAlert(syslog)) {
            disSasAlert(syslog, obj);
        } else if (syslog.split(",").length >= 6) {
            obj.put("log_type", "fw");
            obj.put("event_type", "system");
            obj.put("log_des", "网康 - 防火墙 - 系统");
            disSystem(syslog, obj);
        }
        return obj;
    }

    /**
     * 系统报警日志, 时间:2018-03-27 08:09:42, 类型:系统硬件-Bypass, 描述:设备处于硬件Bypass状态
     */
    private static void disSasAlert(String syslog, JSONObject obj) {
        obj.put("log_type", "sas");
        obj.put("event_type", "alarm");
        obj.put("log_des", "网康 - 防火墙 - 告警");
        String msg = syslog.substring(syslog.indexOf("类型:"));
        JSONObject o = ParseMessageKv.parseMessage7(msg);
        obj.put("message_content", o.getStr("描述"));
        obj.put("opt_type", o.getStr("类型"));
    }

    private static boolean isSasAlert(String syslog) {
        return StringUtil.containsAll(syslog, "类型:", "时间:", "描述:");
    }

    /**
     * <182>Oct 22 10:20:07 NS : 操作日志, 时间:2019-10-22 10:18:00, 来源:用户(UI), 类型:系统配置, 用户:ns25000{2.74.24.23}, 描述:系统设置:syslog配置 syslog开关 开启服务器IP：2.74.24.21，端口：514，编码：UTF-8，上传日志类型：操作日志，系统报警日志
     */
    private static void disSasOpt(String syslog, JSONObject obj) {
        obj.put("log_type", "sas");
        obj.put("event_type", "opt");
        obj.put("log_des", "网康 - 防火墙 - 操作");
        String msg = syslog.substring(syslog.indexOf("来源:"));
        JSONObject o = ParseMessageKv.parseMessage7(msg);
        obj.put("user_name", o.getStr("用户"));
        obj.put("data_source", o.getStr("来源"));
        obj.put("message_content", o.getStr("描述"));
        obj.put("opt_type", o.getStr("类型"));
    }

    private static boolean isSasOptLog(String syslog) {
        return StringUtil.containsAll(syslog, "时间:", "来源:", "用户:");
    }

    /**
     * <133> 0,1571380379,NGFWweb_login,5,,NSLOG_SYSLOG ID=NS_GUI_LOGIN_SUCCESS,PARA=2.74.24.21;admin;6
     * <133> 0,1571380368,NGFWweb_login,5,,NSLOG_SYSLOG ID=NS_GUI_LOGOUT,PARA=2.74.24.21;admin
     *
     * <134> 1,1571380359,admin,2.74.24.21,1,save,0,save
     * <134> 1,1571380355,admin,2.74.24.21,1,commit,0,commit
     * <134> 1,1571380291,admin,2.74.24.21,1,set,0,set system log-settings url only-url-main
     * <134> 1,1571380287,admin,2.74.24.21,1,set,0,set system log-settings traffic-log start
     * <134> 1,1570857229,admin,172.28.15.176,1,delete,0,delete system ntp server
     * <134> 1,1571380281,admin,2.74.24.21,1,set,0,set system log-settings system {<br/>     crash {<br/>          send-syslog hb-1-1;<br/>     }<br/>     emergency {<br/>          send-syslog hb-1-1;<br/>     }<br/>     error {<br/>          send-syslog hb-1-1;<br/>     }<br/>     expedited {<br/>          send-syslog hb-1-1;<br/>     }<br/>     information {<br/>          send-syslog hb-1-1;<br/>     }<br/>     notice {<br/>          send-syslog hb-1-1;<br/>     }<br/>     warning {<br/>          send-syslog hb-1-1;<br/>     }<br/>}
     */
    private static void disSystem(String syslog, JSONObject obj) {
        String[] msg = syslog.split(",");
        if (syslog.contains("NGFWweb_")) {
            obj.put("opt_type", msg[2].trim());
            obj.put("event_level", NumberUtil.parseInt(msg[3]));
            String[] split = msg[6].split(";");
            obj.put("source_ip", split[0].split("=")[1].trim());
            obj.put("user_name", split[1]);
            return;
        }
        if (msg.length > 6 && NumberUtil.isNumber(msg[6])) {
            obj.put("user_name", msg[2]);
            obj.put("source_ip", msg[3]);
            obj.put("opt_type", msg[4]);
            obj.put("cmd", msg[5]);
            StringBuilder builder = new StringBuilder(msg[7]);
            for (int i = 1; i <= msg.length - 8; i++) {
                builder.append(msg[7 + i]);
            }
            obj.put("message_content", builder.toString());
        }
    }

    public static void main(String[] args) {
        String sys1 = "<182>Oct 22 10:20:07 NS : 操作日志, 时间:2019-10-22 10:18:00, 来源:用户(UI), 类型:系统配置, 用户:ns25000{2.74.24.23}, 描述:系统设置:syslog配置 syslog开关 开启服务器IP：2.74.24.21，端口：514，编码：UTF-8，上传日志类型：操作日志，系统报警日志\n";
        sys1 = "<182>Oct 22 10:20:07 NS : 操作日志, 时间:2019-10-22 10:18:00, 来源:用户(UI), 类型:系统配置, 用户:ns25000{2.74.24.23}, 描述:系统设置:syslog配置 syslog开关 开启服务器IP：2.74.24.21，端口：514，编码：UTF-8，上传日志类型：操作日志，系统报警日志";
//        sys1="系统报警日志, 时间:2018-03-27 08:09:42, 类型:系统硬件-Bypass, 描述:设备处于硬件Bypass状态";
        JSONObject obj = new JSONObject();
        obj.put("syslog", sys1);
        System.out.println(JSONUtil.parseObj(parse(obj.toString())).toJSONString(2));
    }
}