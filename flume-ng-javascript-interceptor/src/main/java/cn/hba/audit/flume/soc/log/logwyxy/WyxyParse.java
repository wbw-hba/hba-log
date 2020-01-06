package cn.hba.audit.flume.soc.log.logwyxy;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 功能区防火墙
 *
 * @author wbw
 * @date 2019/9/17 11:29
 */
public class WyxyParse {

    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        obj.put("manufacturers_name", "wyxy");
        obj.put("log_type", "fw");
        if (isWyxyLog(syslog)) {
            return logParse(syslog, obj);
        }

        return null;
    }

    /**
     * 格式：<158>webui: devid=0 date="2019/07/02 16:39:33" dname=themis logtype=9 pri=6 ver=0.3.0
     * mod=webui from=2.74.24.24 user=administrator agent="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36"
     * act=显示 page="Syslog服务器" dsp_msg="显示Syslog服务器页面" fwlog=0
     * <p>
     * 格式：<157>logserver: devid=0 date="2019/07/02 16:39:32" dname=themis logtype=9 pri=5 ver=0.3.0 mod=logserver
     * act=设置 result=0 cmd="logserver 设置 地址 2.74.24.24 端口 5140" user=administrator dsp_msg="设置 2.74.24.24" fwlog=0
     */
    private static Object logParse(String syslog, JSONObject obj) {
        String head = syslog.split("devid=")[0].trim();
        if (head.endsWith(":")) {
            head = head.substring(0, head.length() - 1);
        }
        if (head.contains(" ")) {
            String[] split = head.split(" ");
            obj.put("event_type", split[split.length - 1]);
        } else {
            obj.put("event_type", head.split(">")[1]);
        }
        String msg = syslog.split(obj.getStr("event_type") + ":")[1].trim();
        JSONObject object = ParseMessageKv.parseMessage5(msg);
        WyxyJsonParse.dis(object,obj);
        WyxyJsonDis.dis(object,obj);
        return obj;
    }

    private static boolean isWyxyLog(String syslog) {
        return StringUtil.containsAll(syslog, " devid=", " dname=", " logtype=", " pri=", " ver=", " date=");
    }

    public static void main(String[] args) {
        String syslog = "<157>logserver: devid=0 date=\"2019/07/02 16:39:32\" dname=themis logtype=9 pri=5 ver=0.3.0 mod=logserver act=设置 result=0 cmd=\"logserver 设置 地址 2.74.24.24 端口 5140\" user=administrator dsp_msg=\"设置 2.74.24.24\" fwlog=0";
        JSONObject object = JSONUtil.createObj();
        object.put("syslog", syslog);

        Object parse = parse(object.toString());
        System.out.println(JSONUtil.parseObj(parse).toJSONString(2));
    }
}
