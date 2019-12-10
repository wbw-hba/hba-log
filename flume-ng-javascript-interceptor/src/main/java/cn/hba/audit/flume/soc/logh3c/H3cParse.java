package cn.hba.audit.flume.soc.logh3c;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * H3C 日志解析
 *
 * @author wbw
 * @date 2019/11/18 13:33
 */
class H3cParse {

    static Object parseSyslog(String body) {
        JSONObject object = JSONUtil.parseObj(body);
        String syslog = object.getStr("syslog");
        object.put("manufacturers_name", "h3c");
        object.put("log_type", "network");

        String[] split = syslog.split(" %%");
        String[] host = split[0].trim().split(" ");
        object.put("hostname", host[host.length - 1]);
        String[] head = split[1].split(":");
        String[] he = head[0].split("/");
        object.put("event_type", he[0]);
        object.put("event_level", he[1]);
        object.put("abstract_msg", he[2].trim());
        object.put("log_des", "h3c - 网络 - " + he[0]);
        object.put("message_content", split[1].substring(split[1].indexOf(":") + 1));
        return object;
    }
}
