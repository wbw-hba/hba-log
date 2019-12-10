package cn.hba.audit.flume.soc.logss;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 解析山石告警信息
 *
 * @author lizhi
 * @date 2019/9/9 14:21
 */
public class BastionSsHost {

    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        obj.put("log_type", "fw");

        String syslog = obj.getStr("syslog");
        initSyslog(syslog, obj);
        String messageContent = obj.getStr("message_content");
        if (messageContent.contains("success")) {
            obj.put("result", "成功");
        } else if (messageContent.contains("failed")) {
            obj.put("result", "失败");
        } else if (messageContent.contains("deleted")) {
            obj.put("result", "删除");
        }
        String optType = obj.getStr("opt_type").toLowerCase();
        String eventModule = obj.getStr("event_type").toLowerCase();
        String newsId = obj.getStr("news_id");
        if ("aaa".equals(optType)) {
            SsAaaParse.aaaSyslog(syslog, obj);
            //解析等级
            obj.put("event_level", 6);
            obj.put("log_des", "山石 - 防火墙 - aaa认证");
        } else if (newsId.startsWith("460c")) {
            //解析等级
            SsSecurityParse.securitySyslog(syslog, obj);
            obj.put("event_level", 3);
            obj.put("log_des", "山石 - 防火墙 - 攻击防护");
        } else if ("mgmt".equals(optType)) {
            //解析等级
            SsMgmtParse.mgmtSyslog(syslog, obj);
            obj.put("event_level", 6);
            obj.put("log_des", "山石 - 防火墙 - 配置 - 系统管理");
        } else if (newsId.startsWith("424")) {
            //解析等级
            SsAlarmParse.alarmSyslog(syslog, obj);
            obj.put("event_level", 4);
            obj.put("log_des", "山石 - 防火墙 - 告警");
        } else if ("ips".equals(optType) && "threat".equals(eventModule)) {
            SsThreatParse.parse(obj);
            obj.put("event_level", 2);
        }
        obj.put("manufacturers_name", "ss");
        disLogManufacturers(obj, optType);
        if (obj.containsKey("message_content_explain")) {
            obj.put("message_content_explain", obj.getStr("message_content_explain").replaceAll("\n", ""));
        }
        return obj;
    }

    private static void disLogManufacturers(JSONObject obj, String optType) {
        if (!obj.containsKey("manufacturers")) {
            switch (obj.getStr("event_type").toLowerCase()) {
                case "event":
                    obj.put("log_des", "山石 - 防火墙 - 事件 - " + optType);
                    break;
                case "ips":
                    obj.put("log_des", "山石 - 防火墙 - 入侵防御 - " + optType);
                    obj.put("event_level", 2);
                    break;
                case "data security":
                    obj.put("log_des", "山石 - 防火墙 - 数据安全 - " + optType);
                    break;
                case "ei":
                    obj.put("log_des", "山石 - 防火墙 - 共享接入 - " + optType);
                    break;
                case "debug":
                    obj.put("log_des", "山石 - 防火墙 - 调试 - " + optType);
                    break;
                case "sandbox":
                    obj.put("log_des", "山石 - 防火墙 - 云沙箱 - " + optType);
                    break;
                case "security":
                    obj.put("log_des", "山石 - 防火墙 - 安全 - " + optType);
                    break;
                case "configuration":
                    obj.put("log_des", "山石 - 防火墙 - 配置 - " + optType);
                    break;
                case "operate":
                    obj.put("log_des", "山石 - 防火墙 - 操作 - " + optType);
                    break;
                case "network":
                    obj.put("log_des", "山石 - 防火墙 - 网络 - " + optType);
                    break;
                case "traffic":
                    obj.put("log_des", "山石 - 防火墙 - 流量 - " + optType);
                    break;
                case "threat":
                    obj.put("log_des", "山石 - 防火墙 - 威胁 - " + optType);
                    break;
                default:
                    obj.put("log_des", "山石 - 防火墙 - " + obj.getStr("event_type").toLowerCase() + " - " + optType);
            }

        }
    }

    private static final Pattern COMPILE = Pattern.compile("(?<=\\()(\\S+)(?=\\))");

    //解析日志头部
    private static void initSyslog(String syslog, JSONObject obj) {
        if (syslog.contains("(")) {
            String[] split = syslog.split(" ");
            //解析事件UUID
            String[] str = split[3].split("\\(");
            obj.put("event_uuid", str[0]);
            //解析信息ID
            obj.put("news_id", split[4]);
            //解析用户名称
            Matcher mat1 = COMPILE.matcher(split[3]);
            while (mat1.find()) {
                obj.put("user_name", mat1.group());
            }
            obj.put("message_content", syslog.split(syslog.split("@")[1].split(":")[0] + ":")[1].trim());
            obj.put("opt_type", syslog.split("@")[1].split(":")[0]);
            String[] s = syslog.split("@")[0].split(" ");
            obj.put("event_type", s[s.length - 1]);
        }
    }

    public static void main(String[] args) {
        String syslog = "<190>Sep 25 15:11:42 1304415172004335(root) 44243624 Traffic@FLOW: SESSION: 2.240.148.244:8000->172.23.19.2:50844(TCP), application TCP-ANY, interface ethernet1/1, vr trust-vr, policy 2, user -@-, host -, send packets 0,send bytes 0,receive packets 0,receive bytes 0,start time 2019-09-25 15:10:40,close time 2019-09-25 15:11:42,session end,Ageout ";
        String sys2 = "<190>Sep 29 00:06:00 1304415172001433(root) 46083624 Traffic@FLOW: NAT: 180.96.16.254:19419->58.218.194.50:80(TCP), dnat to 172.17.196.129:80, vr trust-vr, user -@UNKNOWN, host -, rule 30 ";
        String sys3 = "<186>Oct 2 21:03:44 1304415172004335(root) 49040209 Event@RES: Trust domain network_manager_ca CA certificate has expired ";

        JSONObject obj = new JSONObject();
        obj.put("syslog", sys3);
        Object parse = parse(obj.toString());
        System.out.println(JSONUtil.parseObj(parse).toJSONString(2));
    }
}


