package cn.hba.audit.flume.soc.log.loglm.sas;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * sas 审计
 *
 * @author wbw
 * @date 2019/9/16 9:15
 */
public class SasParse {

    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog").replaceAll("\t", "").replaceAll("\n", "");
        if (isSasContent(syslog)) {
            obj.put("event_type", "audit");
            sasLogParse(syslog, obj);
        } else if (isSasApply(syslog)) {
            obj.put("event_type", "apply");
            sasApply(syslog, obj);
        } else if (isSystem(syslog)) {
            obj.put("event_type", "system");
            systemParse(syslog, obj);
        } else {
            return null;
        }
        obj.put("manufacturers_name", "lm");
        obj.put("log_type", "sas");
        return obj;
    }

    /**
     * 系统事件
     * <p>
     * 格式：<255>user:weboper;loginip:2.74.24.29;time:2019-09-19 16:25:38;type:2;
     */
    private static void systemParse(String syslog, JSONObject obj) {
        String msg = syslog.split(">")[1];
        JSONObject object = ParseMessageKv.parseMessage2(msg);
        obj.put("user_name", object.getStr("user"));
        obj.put("source_ip", object.getStr("loginip"));
        obj.put("start_time", object.getStr("time"));
        switch (object.getInt("type")) {
            case 1:
                obj.put("opt_type", "登录");
                break;
            case 2:
                obj.put("opt_type", "操作");
                break;
            case 3:
                obj.put("opt_type", "异常");
                break;
            case 4:
                obj.put("opt_type", "自动更新");
                break;
            case 5:
                obj.put("opt_type", "手工更新");
                break;
            case 6:
                obj.put("opt_type", "重启引擎");
                break;
            case 7:
                obj.put("opt_type", "重启设备");
                break;
            default:
                obj.put("opt_type", object.getStr("type"));
        }
        if (!msg.trim().endsWith(";")){
            obj.put("message_content", msg.substring(msg.lastIndexOf(";") + 1));
        }
    }

    /**
     * 应用识别日志 SYSLOG
     * <p>
     * 格式：<1>rule_id:1;time:2015-07-03
     * 14:03:06;module:fw;src_intf:G1/1;dst_intf:;action:accept;proto:tcp;src_addr:10.66.41.2;src_p
     * ort:54105;dst_addr:125.39.240.164;dst_port:80;src_addr_nat:;src_port_nat:;dst_addr_nat:;dst
     * _port_nat:;info:;user:;app_name:HTTP
     * <p>
     * 格式：<1>rule_id:1;time:2015-07-03
     * 14:03:06;module:fw;src_intf:G1/1;dst_intf:;action:accept;proto:tcp;src_addr:10.66.41.2;src_p
     * ort:54103;dst_addr:61.147.124.120;dst_port:80;src_addr_nat:;src_port_nat:;dst_addr_nat:;dst
     * _port_nat:;info:;user:;app_name:网站浏览
     */
    private static void sasApply(String syslog, JSONObject obj) {
        String log = syslog.substring(syslog.indexOf(">") + 1);
        JSONObject jsonObject = ParseMessageKv.parseMessage2(log);
        SasJsonDis.dispose(jsonObject, obj);
        obj.put("log_des", "绿盟 - sas - 应用识别");
    }


    /**
     * 内容审计事件 SYSLOG
     * <p>
     * 格式：<5>time:2013-10-23
     * 18:41:30;card:eth2;sip:10.8.170.163;smac:78:2B:CB:A3:04:50;sport:61569;dip:61.155.141.1
     * 7;dmac:D8:24:BD:89:78:C6;dport:80;user:;ruleid:1;scmid:340001;
     * scmname:网页浏览;level:1;alerted:1;dropped:0;cat:1;type:WebPage;
     * info0:www.ifeng.com;info1:;info2:;info3:;info4:;info5:;info6:;info7:;info8:;info9:;info10:;key
     * word:ifeng 大连;
     * restore:2013/10/23/18/41/1AEFE6DC1FEB49E5A66A289B0FD385B8.gzip
     * <p>
     * 格式：<5>time:2013-10-23
     * 18:49:33;card:eth2;sip:10.8.15.1;smac:00:1A:A0:AB:09:7F;sport:3779;dip:220.181.15.150;d
     * mac:00:13:80:5C:3B:80;dport:80;user:;ruleid:1;scmid:340003;
     * scmname:电子邮件;level:1;alerted:1;dropped:0;cat:4;type:126 邮箱;
     * info0:xionghuagen@126.com;info1:cjcse@sohu.com;info2:atts;info3:;info4:;info5:;info6:;inf
     * o7:;info8:;info9:;info10:;keyword:;restore:2013/10/23/18/49/58EF0203F18F4E3A86059129C
     * DF77C89.eml
     */
    private static void sasLogParse(String syslog, JSONObject obj) {
        String log = syslog.substring(syslog.indexOf(">") + 1);
        JSONObject jsonObject = ParseMessageKv.parseMessage2(log);
        SasJsonDis.dispose(jsonObject, obj);
        obj.put("log_des", "绿盟 - sas - 内容审计事件");
    }

    public static boolean isSas(String syslog) {
        return isSasApply(syslog) || isSasContent(syslog) || isSystem(syslog);
    }

    private static boolean isSasApply(String syslog) {
        if (!syslog.contains(">rule_id:")) {
            return false;
        }
        String log = syslog.substring(syslog.indexOf(">") + 1);
        JSONObject jsonObject = ParseMessageKv.parseMessage2(log);
        return jsonObject.containsKey("rule_id") && jsonObject.containsKey("module")
                && jsonObject.containsKey("app_name") && jsonObject.containsKey("dst_port");
    }

    private static boolean isSasContent(String syslog) {
        if (!syslog.contains(">time:")) {
            return false;
        }
        String log = syslog.substring(syslog.indexOf(">") + 1);
        JSONObject jsonObject = ParseMessageKv.parseMessage2(log);
        return jsonObject.containsKey("ruleid") && jsonObject.containsKey("time") && jsonObject.containsKey("card") && jsonObject.containsKey("sip")
                && jsonObject.containsKey("sport") && jsonObject.containsKey("smac") && jsonObject.containsKey("dip");
    }


    private static boolean isSystem(String syslog) {
        return StringUtil.containsAll(syslog, "user:", ";time:", ";loginip:");
    }

    public static void main(String[] args) {
        String log = "<255>user:weboper;loginip:2.74.24.29;time:2019-09-25 15:42:55;type:1;\n" +
                "登录成功";
//        JSONObject jsonObject = ParseMessageKv.parseMessage2(log.substring(log.indexOf(">") + 1));
//        System.out.println(jsonObject.toJSONString(2));
//        System.out.println(log.substring(log.indexOf(";")+1));
        JSONObject object = JSONUtil.createObj();
        object.put("syslog", log);
        System.out.println(JSONUtil.parseObj(parse(object.toString())).toJSONString(2));
    }
}
