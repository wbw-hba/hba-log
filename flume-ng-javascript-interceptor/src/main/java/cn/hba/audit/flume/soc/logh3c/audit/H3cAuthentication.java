package cn.hba.audit.flume.soc.logh3c.audit;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 身份验证日志
 *
 * @author wbw
 * @date 2019/11/29 16:21
 */
public class H3cAuthentication {

    /**
     * 是否为 身份验证日志
     *
     * @param syslog syslog
     * @return flag
     */
    public static boolean isAuthentication(String syslog) {
        return StrUtil.containsAny(syslog, "Login(web)", "Login(gui)", "Login(tui)", "Login(api)")
                && StrUtil.containsAny(syslog, "login authorize success", "login authorize fail");
    }

    /**
     * 身份认证日志
     */
    public static Object authParse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        authDisLog(syslog,obj);
        return obj;
    }
    /**
     * 日志格式：
     * <134>Dec 04 15:12:35 node1 H3C-A2020-G: Login(web)(service=native server=None(None) account=None identity=h3cadmin from=172.31.255.2 login authorize success)
     * Login(web)(service=native server=None(None) account=None identity=h3cadmin from=172.31.255.2 login authorize success)
     */
    private static void authDisLog(String syslog, JSONObject obj) {
        String[] splitStr = syslog.split(": ")[1].split("\\)\\(");
        String sysStr = splitStr[1].substring(0, splitStr[1].length() - 1);
        JSONObject bodyObj = ParseMessageKv.parseMessage5(sysStr);
        int i = bodyObj.getStr("from").indexOf(" ");
        String result = bodyObj.getStr("from").substring(i + 1);
        obj.put("event_title", splitStr[0] + ")");
        obj.put("login_ip", bodyObj.getStr("from").substring(0, i));
        obj.put("login_result", result);
        addLog(bodyObj, obj);
        //必备字段
        obj.put("event_type", "auth");
        obj.put("log_des", "h3c-运维审计-身份验证");
    }

    /**
     * 资产认证日志
     */
    public static Object propertyParse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        propertyDisLog(syslog,obj);
        return obj;
    }

    /**
     * 是否为 资产验证日志
     *
     * @param syslog syslog
     * @return flag
     */
    public static boolean isProperty(String syslog) {
        return syslog.split(": ")[1].split(" ").length == 9 && StrUtil.containsAny(syslog, "interface");
    }

    /**
     * 日志格式：
     * <134>Dec 04 15:12:35 node1 H3C-A2020-G: bljuser10 from interface(service=gui login server=group10-3(192.168.109.71) account=any identity=bljuser10 from=192.168.6.154 )
     * bljuser10 from interface(service=gui login server=group10-3(192.168.109.71) account=any identity=bljuser10 from=192.168.6.154 )
     */
    private static void propertyDisLog(String syslog, JSONObject obj) {
        String splitStr = syslog.split(": ")[1];
        String sysStr = splitStr.substring(splitStr.indexOf("(") + 1, splitStr.length() - 2);
        JSONObject bodyObj = ParseMessageKv.parseMessage5(sysStr);
        obj.put("event_title", splitStr.substring(0, splitStr.indexOf("(")));
        obj.put("login_ip", bodyObj.getStr("from"));
        addLog(bodyObj, obj);
        //必备字段
        obj.put("event_type", "property");
        obj.put("log_des", "h3c-运维审计-资产");
    }

    /**
     * 公共字段
     */
    private static void addLog(JSONObject bodyObj, JSONObject obj) {
        if (bodyObj.containsKey("service")) {
            obj.put("auth_method", bodyObj.getStr("service"));
        }
        if (bodyObj.containsKey("server")) {
            obj.put("asset_name", bodyObj.getStr("server"));
        }
        if (bodyObj.containsKey("account")) {
            obj.put("user_name", bodyObj.getStr("account"));
        }
        if (bodyObj.containsKey("identity")) {
            obj.put("user_id", bodyObj.getStr("identity"));
        }
        //公共必备字段
        obj.put("log_type", "operation");
        obj.put("manufacturers_name", "h3c");
        obj.put("manufacturers_facility", "运维");
        obj.put("facility_type", "运维");

    }

}
