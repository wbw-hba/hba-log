package cn.hba.audit.flume.soc.logjs;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;


/**
 * 金山
 *
 * @author wbw
 * @date 2019/9/6 11:17
 */
public class SyslogParseJs implements SyslogParse {

    @Override
    public Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        obj.put("manufacturers_name", "js");
        obj.put("log_type", "gateway");
        obj.put("event_type", "virus");
        obj.put("log_des", "金山 - 网关 - 病毒");
        String[] msg = syslog.split("] ");
        obj.put("event_type", msg[0].substring(msg[0].lastIndexOf("[") + 1).toLowerCase());
        if (StringUtil.containsAll(msg[1], "id=", "time=", "fw=")) {
            JSONObject object = dis(msg[1]);
            obj.putAll(object);
        }
        return obj;
    }

    private static JSONObject dis(String msg) {
        JSONObject object = new JSONObject();
        String[] s = msg.trim().split(" ");
        String temp = "";
        for (String s1 : s) {
            if (s1.contains("=")) {
                int ms = s1.indexOf("=");
                temp = s1.substring(0, ms);
                object.put(temp, s1.substring(ms + 1));
            } else {
                object.put(temp, object.getStr(temp) + " " + s1);
            }
        }
        return object;
    }

    /**
     * <137>vgm mdg[1617]: [ALERT] id=mdg:app time='2019-10-22 10:20:05' fw=vgm dev=eth1 pri=5 proto=http src=172.17.211.7:35827 dst=172.17.211.6:80 op=GET url='172.17.211.6/mobile/plugin/download.jsp?sessionkey=31251cbb-b7d2-48b7-8ff1-1721d4ce5e45&url=460617&filename=%e5%be%90%e4%bf%a1%e8%81%94%e5%8a%9e%e3%80%902019%e3%80%9184%e5%8f%b7.pdf&download=1&f_weaver_belongto_usertype=&f_weaver_belongto_userid=&fileid=460617' size=1228323 md5=d8ad2c8aa16b2c174b145088966207c9 action=alert msg='PDF document, version 1.7' category='Download File'
     * <140>vgm mvd: [WARNING] exceed the max connection limit: 12
     * <141>vgm logmon: [NOTICE] capture.kernel_drops 266078375 packets
     * <137>vgm mdg[1617]: [ALERT] id=mdg:flow time='2019-10-22 14:22:45' fw=vgm dev=eth1 pri=4 proto=TCP src=42.236.10.116:48293 dst=172.30.252.11:80 rule=2403332 msg='CINS Active Threat Intelligence Poor Reputation IP group 33' category='Suspicious IP'
     */

    public static void main(String[] args) {
        String sys = "<137>vgm mdg[1617]: [ALERT] id=mdg:app time='2019-10-22 10:20:05' fw=vgm dev=eth1 pri=5 proto=http src=172.17.211.7:35827 dst=172.17.211.6:80 op=GET url='172.17.211.6/mobile/plugin/download.jsp?sessionkey=31251cbb-b7d2-48b7-8ff1-1721d4ce5e45&url=460617&filename=%e5%be%90%e4%bf%a1%e8%81%94%e5%8a%9e%e3%80%902019%e3%80%9184%e5%8f%b7.pdf&download=1&f_weaver_belongto_usertype=&f_weaver_belongto_userid=&fileid=460617' size=1228323 md5=d8ad2c8aa16b2c174b145088966207c9 action=alert msg='PDF document, version 1.7' category='Download File'\n";
        JSONObject object = JSONUtil.createObj();
        sys = "<140>vgm mvd: [WARNING] exceed the max connection limit: 12";
        object.put("syslog", sys);
        System.out.println(JSONUtil.parseObj(new SyslogParseJs().parse(object.toString())).toJSONString(2));
    }
}
