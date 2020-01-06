package cn.hba.audit.flume.soc.log.logws;

import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 访问日志
 *
 * @author wbw
 * @date 2019/11/29 9:00
 */
class WsVisitLog {

    /**
     * 是否为 访问日志
     *
     * @param syslog 原始日志
     * @return flag
     */
    static boolean isVisitLog(String syslog) {
        return StringUtil.containsAll(syslog, "devicename=", "->") && StrUtil.trim(syslog).endsWith("]");
    }

    /**
     * 日志格式：
     * 2010-02-09 13:35:44-:192.165.1.150:46->www.sohu.com devicename=xxxx /searchbook7.asp POST 64 ]
     */
    static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        disBody(syslog, obj);
        // 必备字段
        obj.put("log_type", "flow");
        obj.put("event_type", "visit");
        obj.put("manufacturers_name", "网神");
        obj.put("manufacturers_facility", "WEB");
        obj.put("facility_type", "系统防护");
        obj.put("log_des", "网神 - WAF - 访问日志");
        return obj;
    }

    /**
     * 处理日志
     */
    private static void disBody(String syslog, JSONObject obj) {
        String[] head = syslog.split("devicename=");
        String[] he = StrUtil.trim(head[0]).split("->");
        obj.put("site_name", he[he.length - 1]);
        String[] h = he[0].split(":");
        obj.put("port", h[h.length - 1]);
        obj.put("ip", h[h.length - 2]);
        String[] bo = head[1].split(" ");
        obj.put("facility_hostname", bo[0]);
        obj.put("url", bo[1]);
        obj.put("http_method", bo[2]);
        obj.put("package_size", bo[3]);
    }


}
