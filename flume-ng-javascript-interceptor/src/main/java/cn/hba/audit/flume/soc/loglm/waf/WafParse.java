package cn.hba.audit.flume.soc.loglm.waf;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

import java.util.HashMap;
import java.util.Objects;

/**
 * WAF - WEB应用防火墙
 *
 * @author wbw
 * @date 2019/9/10 14:48
 */
public class WafParse {

    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog").replaceAll("tag: ", "tag:");
        String[] split = syslog.split("tag:waf_log_");
        String[] hh = syslog.split(" waf:")[0].split(" ");
        obj.put("hostname", hh[hh.length - 1]);
        obj.put("manufacturers_name", "lm");
        obj.put("log_type", "waf");
        obj.put("event_type", split[1].split(" ")[0]);
        // 截取 message
        String[] waf = syslog.split(" waf:");
        String message = waf[waf.length - 1];
        message = " waf:" + message;
        // 所有字段解析
        WafJsonDis.jsonDis(ParseMessageKv.parseMessage1(message), obj);
        switch (obj.getStr("event_type")) {
            case "login":
                login(obj);
                break;
            case "op":
                op(obj);
                break;
            case "system_run":
                systemRun(obj);
                break;
            case "wafstat":
                wafstat(obj);
                break;
            case "l4acl":
                acl14(obj);
                break;
            case "ddos":
                ddos(obj);
                break;
            case "deface":
                deface(obj);
                break;
            case "webaccess":
                webaccess(obj);
                break;
            case "arp":
                arp(obj);
                break;
            case "session":
                session(obj);
                break;
            case "websec":
                websec(obj);
                break;
            case "ipblock":
                ipblock(obj);
                break;
            default:
                return null;
        }
        return obj;
    }

    /**
     * 4.7.1 HTTP协议违背
     * <p>
     * 格式：<11>Sep 11 11:23:42 localhost waf: tag:waf_log_websec site_id:1 protect_id:1 dst_ip:58.218.194.222
     * dst_port:80 src_ip:121.7.12.194 src_port:44055 method:UNKNOWN domain:None uri:None alertlevel:MEDIUM
     * event_type:HTTP_Protocol_Validation stat_time:2019-09-11 11:23:38 policy_id:1 rule_id:0 action:Block
     * block:No block_info:None http:��R�J�"�h�[���1on(.IńJ+�s��,��Y<+���v�H�[��x����l��/�>k�}����`��Z�a]�� ��ys��Cj��b��B"F�Ê�e�C�N��|Y��7}���-�ZF�][U�{��j����zs|�^Gޞ�!˥���i<���$�L�wm�� >�vF=6U�>_U�}aOE��e�&��Ƒ�J�4S�B�j���s����k��{^�?�&����o�,�7��Ը���*��@���+��f��zE�<�:�k-�H]3�rm��w�:Z����E�oC�/#ť�����m8�I�U(L ����W�� alertinfo:request method begin with non-capital letters or over load content-length proxy_info:None characters:None count_num:1 protocol_type:HTTP wci:None wsi:None country:Singapore correlation_id:0 site_name:default_v4 vsite_name:None
     */
    private static void websec(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - HTTP协议违背");
    }

    /**
     * 4.6 会话追踪日志
     * 格式：<11>Sep 11 11:23:42 localhost waf: tag:waf_log_session event_type:Session_Track stat_time:2015-09-24 17:15:59 dst_ip:20.20.20.208 dst_port:80 wci:0PHkH37arWzQoLXGytgXtRtkGpZXZPj0Okn/Pg== wsi:B8cCLxwkkTPpDVNzr0H8qCEeIDRNvwNWT4Dylg== user_name:Zhangsan country:China
     */
    private static void session(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - 会话追踪");
    }

    /**
     * 4.5 防护日志
     * <p>
     * 格式：waf-g2 waf: waf: tag: waf_log_arp stat_time:2015-09-24 15:57:00 alertlevel:HIGH event_type:ARP attack_type:MAC conflict src_ip:140.140.1.200 src_mac:169790446168692 dst_ip:140.140.1.5 dst_mac:100525348495872 status:Attempting action:Block def_ip:140.140.1.5 def_mac:43533807979536 conflit_mac:100525348495872 count_num:1
     */
    private static void arp(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - ARP防护");
    }

    /**
     * 格式：<11>Sep 11 11:23:29 localhost waf: tag:waf_log_webaccess site_id:1564821742 protect_id:2564821808
     * stat_time:2019-09-11 11:23:23 alertlevel:LOW event_type:WEB Access Logs dst_ip:58.218.194.20 dst_port:80
     * url:/zgxz/Template/Default/main2019/js/lib/pagination/mricode.pagination.css src_ip:125.119.9.71
     * src_port:28462 method:GET
     * agent:Mozilla/4.0%20(compatible;%20MSIE%207.0;%20Windows%20NT%206.1;%20WOW64;%20Trident/7.0;%20SLCC2;%20.NET%20CLR%202.0.50727;
     * %20.NET%20CLR%203.5.30729;%20.NET%20CLR%203.0.30729;%20.NET4.0C;%20.NET4.0E;%20Media%20Center%20PC%206.0)
     * count_num:1 wa_host:www.xz.gov.cn wa_referer:https://www.baidu.com/ http_protocol:HTTP/1.1
     * protocol_type:HTTP wci:None wsi:None country:China action:Other req_content_type:None req_content_len:0
     * res_content_type:text/css res_content_len:812 waf_status_code:0 ser_status_code:200 correlation_id:6735248322165038310
     */
    private static void webaccess(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - Web访问");
    }

    /**
     * 4.3 防篡改日志
     * <p>
     * 格式：<11>Sep 11 11:23:29 localhost waf: tag:waf_log_deface site_id:1351218462  protect_id:1  stat_time:2012-12-11 13:13:06  alertlevel:MEDIUM  event_type:Anti_Dafacement  dst_ip:10.67.1.95  dst_port:20  url:www.websec.com  reason: Illegally changing the original contents
     */
    private static void deface(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - 防篡改");
    }

    /**
     * 4.8 高危IP日志
     * <p>
     * 格式：<14>Aug 3 10:26:10 localhost waf: tag:waf_log_ipblock stat_time:2016-08-29 15:40:00 event_type:IP_Block alertlevel:HIGH src_ip:10.67.1.103 dst_ip:10.67.2.249 attack_type:DDos
     */
    private static void ipblock(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - 高危IP");
    }

    /**
     * 4.2 DDoS攻击日志
     * 格式：<14>Aug 3 10:26:10 localhost waf: tag:waf_log_ddos  stat_time:2012-12-11 13:13:06  alertlevel:LOW  event_type: SYN_Flood  dst_ip:10.24.18.2  dst_port:80  action: ENTER DEFEND MODE
     */
    private static void ddos(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - DDoS攻击");
    }

    /**
     * 4.1 网络层访问控制日志
     * <p>
     * 格式：<14>Aug 3 10:26:10 localhost waf: tag:waf_log_l4acl stat_time:2012-12-11 13:13:06  alertlevel:LOW  event_type:IP_ACL  dst_ip:10.67.1.30  dst_port:28490  src_ip:10.67.1.68  src_port:80  protocol:tcp  policy_id:33826582  policy_desc:eth1  action:Accept  count_num:2
     */
    private static void acl14(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - 网络层访问控制");
    }

    /**
     * 状态日志
     * <p>
     * 格式：<14>Aug 3 10:26:10 localhost waf: tag:waf_log_wafstat stat_time:2019-08-03 10:25:00 cpu:1 mem:11
     */
    private static void wafstat(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - 状态");
    }

    /**
     * 系统运行日志
     * <p>
     * 格式：<14>Aug 6 01:07:04 localhost waf: tag:waf_log_system_run stat_time:2019-08-06 01:07:04
     * type:DEV_RESOURCE source:monitor info:Disk / usage 89% is over the normal mode threshold value 85%.
     */
    private static void systemRun(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - 系统运行");
    }

    /**
     * 操作日志
     * <p>
     * 格式：<14>Aug 5 10:02:24 localhost waf: tag:waf_log_op stat_time:2019-08-05 10:02:24 src_ip:2.75.160.104
     * user:admin session_id:73df143a1c09fb71b272a77db2eb4645 desc:[["增加", 1], [" 虚拟站点：%1", 1, ["xz.gov.cn"]]]
     * op_type:Security Configuration result:success
     */
    private static void op(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - 操作");
    }

    /**
     * 登录日志
     * <p>
     * 格式：<14>Jul 10 19:46:50 localhost waf: tag:waf_log_login stat_time:2019-07-10 19:46:50 src_ip:2.75.160.102
     * user:admin password: session_id:c9de22295360a4a6613b3a0585e7c0ba desc: op_type:Login result:fail src_port:64034
     */
    private static void login(JSONObject obj) {
        obj.put("log_des", "绿盟 - waf - 登录");
    }


    public static void main(String[] args) {
        String log = "<14>Aug 3 10:26:10 localhost waf: tag:waf_log_wafstat stat_time:2019-08-03 10:25:00 cpu:1 mem:11";
        String sys2 = "<11>Oct 17 07:05:00 localhost waf: tag:waf_log_websec site_id:1  protect_id:1  dst_ip:58.218.194.133  dst_port:80  src_ip:118.24.141.69  src_port:59313  method:POST  domain:58.218.194.133  uri://config/AspCms%5fConfig.asp  alertlevel:HIGH  event_type:Webshell  stat_time:2019-10-17 07:04:56  policy_id:2359295  rule_id:8912897  action:Block  block:No  block_info:None  http:POST //config/AspCms_Config.asp HTTP/1.1";
        JSONObject obj = JSONUtil.createObj();
        obj.put("syslog", sys2);
        System.out.println(Objects.requireNonNull(JSONUtil.parse(parse(obj.toString()))).toJSONString(2));
    }
}
