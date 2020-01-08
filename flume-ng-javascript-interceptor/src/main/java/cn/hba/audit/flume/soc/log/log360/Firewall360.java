package cn.hba.audit.flume.soc.log.log360;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 防火墙
 *
 * @author wbw
 * @date 2020/1/7 13:52
 */
public class Firewall360 {
    /**
     * 日志格式：
     * <6> Dec 28 15:22:35 2019 NSG devid="3" dname="NSG" serial="7d06c102f487bdf2488f217d8f79b835c1c5d95a" module="flow"
     * severity="info" vsys="root-vsys" type="traffic-end" session_id="3463080" time="1577517755" addr_src="192.168.134.117"
     * addr_dst="192.168.181.105" nataddr_src="::" nataddr_dst="::" natport_src="0" natport_dst="0" proto="TCP" hit_num="0"
     * focus_type="NO" action="permit" session_time="5170863" sess_nth="61" sess_dev_id="0" port_src="51955" port_dst="50621"
     * user_src="" user_dst="" locale_src="内网" locale_dst="内网" interface_src="s2xg3" interface_dst="s2xg1" zone_src=""
     * zone_dst="" appname="FTP" rule="ftp同步" profile="" non_standard_port="NO" app_category="APP_NETWORK" app_risk="5"
     * asset_os_src="" asset_os_dst="" asset_name_src="" asset_name_dst="" asset_type_src="" asset_type_dst="" duration="1"
     * bytes_sent="178" bytes_received="192" pkts_sent="3" pkts_received="3" total_sess="0" from_tunnel="" to_tunnel=""
     *
     * @param body 主体
     * @return obj
     */
    static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        // 处理所有日志
        disAllLog(syslog, obj);
        // 处理日志类型
        disLogType(obj);

        return obj;
    }

    /**
     * 是否为防火墙日志
     *
     * @param syslog 日志
     * @return flag
     */
    static boolean isFirewallLog(String syslog) {
        return StringUtil.containsAll(syslog, "devid=", "dname=", "serial=", "module=", "severity=", "vsys=", "type=");
    }

    /**
     * 处理日志类型
     *
     * @param obj 对象
     */
    private static void disLogType(JSONObject obj) {
        String module = obj.getStr("module_name");

        if (module.contains("flow")) {
            // 流量日志
            obj.put("log_type", "flow");
            obj.put("event_type", "flow");
        } else if (module.contains("threat")) {
            // 威胁日志（threat）
            obj.put("log_type", "threat");
            obj.put("event_type", "other");
        } else if (module.contains("dns")) {
            // 域名日志（dns）
            obj.put("log_type", "network");
            obj.put("event_type", "dns");
        } else if (module.contains("url")) {
            // URL 过滤日志（url）
            obj.put("log_type", "network");
            obj.put("event_type", "url");
        } else if (module.contains("mail")) {
            // 邮件过滤日志（mail）
            obj.put("log_type", "network");
            obj.put("event_type", "mail");
        } else if (module.contains("operate")) {
            // 配置日志（operate）
            obj.put("log_type", "opconf");
            obj.put("event_type", "configuration");
        } else if (module.contains("system")) {
            // 事件日志 system
            obj.put("log_type", "sysrun");
            obj.put("event_type", "other");
        } else {
            obj.put("log_type", "other");
            obj.put("event_type", "other");
        }

        obj.put("manufacturers_name", "奇安信");
        obj.put("manufacturers_facility", "跨网防火墙");
        obj.put("facility_type", "防火墙");
        obj.put("log_des", "奇安信 - 跨网防火墙");
    }

    /**
     * 处理所有日志
     *
     * @param syslog 日志
     * @param obj    对象
     */
    private static void disAllLog(String syslog, JSONObject obj) {
        JSONObject objMess = ParseMessageKv.parseMessage6(syslog.substring(syslog.indexOf("devid=")).trim());
        if (objMess.containsKey("asset_type_src")) {
            obj.put("asset_type", objMess.getStr("asset_type_src"));
        }
        if (objMess.containsKey("bytes_received")) {
            obj.put("bytes_received", objMess.getStr("bytes_received"));
        }
        if (objMess.containsKey("type")) {
            obj.put("type", objMess.getStr("type"));
        }
        if (objMess.containsKey("appname")) {
            obj.put("apply_name", objMess.getStr("appname"));
        }
        if (objMess.containsKey("action")) {
            obj.put("conduct_operations", objMess.getStr("action"));
        }
        if (objMess.containsKey("interface_src")) {
            obj.put("src_card", objMess.getStr("interface_src"));
        }
        if (objMess.containsKey("hit_num")) {
            obj.put("attack_num", objMess.getStr("hit_num"));
        }
        if (objMess.containsKey("vsys")) {
            obj.put("vsys", objMess.getStr("vsys"));
        }
        if (objMess.containsKey("natport_dst")) {
            obj.put("nat_dst_ip", objMess.getStr("natport_dst"));
        }
        if (objMess.containsKey("pkts_received")) {
            obj.put("pkts_received", objMess.getStr("pkts_received"));
        }
        if (objMess.containsKey("zone_dst")) {
            obj.put("zone_dst", objMess.getStr("zone_dst"));
        }
        if (objMess.containsKey("module")) {
            obj.put("module_name", objMess.getStr("module"));
        }
        if (objMess.containsKey("profile")) {
            obj.put("profile", objMess.getStr("profile"));
        }
        if (objMess.containsKey("focus_type")) {
            obj.put("focus_type", objMess.getStr("focus_type"));
        }
        if (objMess.containsKey("addr_dst")) {
            obj.put("dest_ip", objMess.getStr("addr_dst"));
        }
        if (objMess.containsKey("proto")) {
            obj.put("protocol_type", objMess.getStr("proto"));
        }
        if (objMess.containsKey("app_risk")) {
            obj.put("app_risk", objMess.getStr("app_risk"));
        }
        if (objMess.containsKey("total_sess")) {
            obj.put("total_sess", objMess.getStr("total_sess"));
        }
        if (objMess.containsKey("app_category")) {
            obj.put("apply_type", objMess.getStr("app_category"));
        }
        if (objMess.containsKey("devid")) {
            obj.put("facility_uuid", objMess.getStr("devid"));
        }
        if (objMess.containsKey("nataddr_src")) {
            obj.put("nat_src_ip", objMess.getStr("nataddr_src"));
        }
        if (objMess.containsKey("zone_src")) {
            obj.put("zone", objMess.getStr("zone_src"));
        }
        if (objMess.containsKey("sess_dev_id")) {
            obj.put("sess_dev_id", objMess.getStr("sess_dev_id"));
        }
        if (objMess.containsKey("port_src")) {
            obj.put("port", objMess.getStr("port_src"));
        }
        if (objMess.containsKey("rule")) {
            obj.put("rule", objMess.getStr("rule"));
        }
        if (objMess.containsKey("asset_name_src")) {
            obj.put("asset_name_src", objMess.getStr("asset_name_src"));
        }
        if (objMess.containsKey("natport_src")) {
            obj.put("nat_src_port", objMess.getStr("natport_src"));
        }
        if (objMess.containsKey("session_time")) {
            obj.put("start_time", objMess.getStr("session_time"));
        }
        if (objMess.containsKey("addr_src")) {
            obj.put("login_ip", objMess.getStr("addr_src"));
        }
        if (objMess.containsKey("duration")) {
            obj.put("duration_time", objMess.getStr("duration"));
        }
        if (objMess.containsKey("user_src")) {
            obj.put("user_src", objMess.getStr("user_src"));
        }
        if (objMess.containsKey("asset_name_dst")) {
            obj.put("asset_name_dst", objMess.getStr("asset_name_dst"));
        }
        if (objMess.containsKey("asset_os_src")) {
            obj.put("asset_os_src", objMess.getStr("asset_os_src"));
        }
        if (objMess.containsKey("dname")) {
            obj.put("facility_hostname", objMess.getStr("dname"));
        }
        if (objMess.containsKey("non_standard_port")) {
            obj.put("non_standard_port", objMess.getStr("non_standard_port"));
        }
        if (objMess.containsKey("severity")) {
            obj.put("log_severity", objMess.getStr("severity"));
        }
        if (objMess.containsKey("locale_dst")) {
            obj.put("dst_addr_state", objMess.getStr("locale_dst"));
        }
        if (objMess.containsKey("asset_type_dst")) {
            obj.put("asset_type_dst", objMess.getStr("asset_type_dst"));
        }
        if (objMess.containsKey("port_dst")) {
            obj.put("dest_port", objMess.getStr("port_dst"));
        }
        if (objMess.containsKey("session_id")) {
            obj.put("session_id", objMess.getStr("session_id"));
        }
        if (objMess.containsKey("nataddr_dst")) {
            obj.put("nat_dst_ip", objMess.getStr("nataddr_dst"));
        }
        if (objMess.containsKey("bytes_sent")) {
            obj.put("send_bytes", objMess.getStr("bytes_sent"));
        }
        if (objMess.containsKey("sess_nth")) {
            obj.put("session_nth", objMess.getStr("sess_nth"));
        }
        if (objMess.containsKey("pkts_sent")) {
            obj.put("outpkt", objMess.getStr("pkts_sent"));
        }
        if (objMess.containsKey("user_dst")) {
            obj.put("user_dst", objMess.getStr("user_dst"));
        }
        if (objMess.containsKey("asset_os_dst")) {
            obj.put("asset_os_dst", objMess.getStr("asset_os_dst"));
        }
        if (objMess.containsKey("serial")) {
            obj.put("facility_numerical_order", objMess.getStr("serial"));
        }
        if (objMess.containsKey("interface_dst")) {
            obj.put("dst_card", objMess.getStr("interface_dst"));
        }
        if (objMess.containsKey("time")) {
            obj.put("time", objMess.getStr("time"));
        }
        if (objMess.containsKey("from_tunnel")) {
            obj.put("from_tunnel", objMess.getStr("from_tunnel"));
        }
        if (objMess.containsKey("locale_src")) {
            obj.put("src_addr_state", objMess.getStr("locale_src"));
        }
    }

    public static void main(String[] args) {
        String ss = "<6> Dec 28 15:22:43 2019 NSG devid=\"3\" dname=\"NSG\" serial=\"7d06c102f487bdf2488f217d8f79b835c1c5d95a\" module=\"flow\" severity=\"info\" vsys=\"root-vsys\" type=\"traffic-end\" session_id=\"3463080\" time=\"1577517763\" addr_src=\"192.168.134.117\" addr_dst=\"192.168.181.105\" nataddr_src=\"::\" nataddr_dst=\"::\" natport_src=\"0\" natport_dst=\"0\" proto=\"TCP\" hit_num=\"0\" focus_type=\"NO\" action=\"permit\" session_time=\"5170863\" sess_nth=\"81\" sess_dev_id=\"0\" port_src=\"61877\" port_dst=\"54970\" user_src=\"\" user_dst=\"\" locale_src=\"内网\" locale_dst=\"内网\" interface_src=\"s2xg3\" interface_dst=\"s2xg1\" zone_src=\"\" zone_dst=\"\" appname=\"FTP\" rule=\"ftp同步\" profile=\"\" non_standard_port=\"NO\" app_category=\"APP_NETWORK\" app_risk=\"5\" asset_os_src=\"\" asset_os_dst=\"\" asset_name_src=\"\" asset_name_dst=\"\" asset_type_src=\"\" asset_type_dst=\"\" duration=\"1\" bytes_sent=\"178\" bytes_received=\"192\" pkts_sent=\"3\" pkts_received=\"3\" total_sess=\"0\" from_tunnel=\"\" to_tunnel=\"\"\n";
        JSONObject objMess = ParseMessageKv.parseMessage6(ss.substring(ss.indexOf("devid=")).trim());
        System.out.println(objMess.toJSONString(2));
    }
}