package cn.hba.audit.flume.soc.log.log360;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 360
 *
 * @author wbw
 * @date 2019/9/6 11:16
 */
public class SyslogParse360 implements SyslogParse {

    @Override
    public Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");

        if (Firewall360.isFirewallLog(syslog)) {
            // 360 防火墙日志
            return Firewall360.parse(body);
        } else if (Bastion360Host.isBastion360(syslog)) {
            // 360 堡垒机
            return Bastion360Host.select(body);
        }
        return null;
    }


    public static void main(String[] args) {
        SyslogParse parse = new SyslogParse360();
        String sys = "20191017 16:00:18 Gateway |5|0x02000465|User|Login|admin|Success|管理员[admin:本地认证]登录系统:IP[2.74.24.21], 接口[GE3], 登录方式[HTTPS],认证服务器为[本地认证], 认证类型[LOCAL].  ";
        sys = "<6> Dec 28 15:22:43 2019 NSG devid=\"3\" dname=\"NSG\" serial=\"7d06c102f487bdf2488f217d8f79b835c1c5d95a\" module=\"flow\" severity=\"info\" vsys=\"root-vsys\" type=\"traffic-end\" session_id=\"3463080\" time=\"1577517763\" addr_src=\"192.168.134.117\" addr_dst=\"192.168.181.105\" nataddr_src=\"::\" nataddr_dst=\"::\" natport_src=\"0\" natport_dst=\"0\" proto=\"TCP\" hit_num=\"0\" focus_type=\"NO\" action=\"permit\" session_time=\"5170863\" sess_nth=\"81\" sess_dev_id=\"0\" port_src=\"61877\" port_dst=\"54970\" user_src=\"\" user_dst=\"\" locale_src=\"内网\" locale_dst=\"内网\" interface_src=\"s2xg3\" interface_dst=\"s2xg1\" zone_src=\"\" zone_dst=\"\" appname=\"FTP\" rule=\"ftp同步\" profile=\"\" non_standard_port=\"NO\" app_category=\"APP_NETWORK\" app_risk=\"5\" asset_os_src=\"\" asset_os_dst=\"\" asset_name_src=\"\" asset_name_dst=\"\" asset_type_src=\"\" asset_type_dst=\"\" duration=\"1\" bytes_sent=\"178\" bytes_received=\"192\" pkts_sent=\"3\" pkts_received=\"3\" total_sess=\"0\" from_tunnel=\"\" to_tunnel=\"\"\n";

        JSONObject object = JSONUtil.createObj();
        object.put("syslog", sys);
        Object res = parse.parse(object.toString());
        System.out.println(JSONUtil.parseObj(res).toJSONString(2));
    }
}
