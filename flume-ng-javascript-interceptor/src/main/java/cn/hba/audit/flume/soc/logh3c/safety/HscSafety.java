package cn.hba.audit.flume.soc.logh3c.safety;

import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * h3c 安全产品
 *
 * @author wbw
 * @date 2019/12/2 10:57
 */
public class HscSafety {

    /**
     * 日志格式：
     * <188>Dec  1 19:36:36 2019 H3C %%10IPS/4/IPS_IPV4_INTERZONE:
     * Protocol(1001)=TCP; Application(1002)=ShouJiBaiDu; SrcIPAddr(1003)=192.168.134.36; SrcPort(1004)=56591;
     * DstIPAddr(1007)=192.168.221.1; DstPort(1008)=82; RcvVPNInstance(1042)=external_vpn; SrcZoneName(1025)=EXTERNAL;
     * DstZoneName(1035)=W7ZIVZIYVZSX5P7VBSEDLK2HZI; PolicyName(1079)=ips_wznetdttdxod5rofa2i3m6kk7u;
     * AttackName(1088)=INFOMATION_GATHER__Robot_Spider_Crawler(Baidu); AttackID(1089)=23302;
     * Category(1090)=InformationDisclosure; Protection(1091)=WebServer; SubProtection(1092)=Any;
     * Severity(1087)=LOW; Action(1053)=Permit & Logging; CVE(1075)=--; BID(1076)=--; MSB(1077)=--; HitDirection(1115)=original;
     * RealSrcIP(1100)=111.206.198.98,222.186.35.134,115.231.25.181; SubCategory(1124)=Spider;
     * <br/>
     * <6> Dec 01 16:15:43 2019 GB-ZWY-HLWQ-J1J2-S-FW-F1050-1&2 %%10session/6/SESSION_IPV4_FLOW:
     * Protocol(1001)=TCP;Application(1002)=http;SrcIPAddr(1003)=192.168.187.20;SrcPort(1004)=32926;NatSrcIPAddr(1005)=112.35.18.188;
     * NatSrcPort(1006)=60295;DstIPAddr(1007)=59.252.162.151;DstPort(1008)=80;NatDstIPAddr(1009)=59.252.162.151;NatDstPort(1010)=80;
     * InitPktCount(1044)=6;InitByteCount(1046)=920;RplyPktCount(1045)=9;RplyByteCount(1047)=3477;RcvVPNInstance(1042)=;
     * SndVPNInstance(1043)=;RcvDSLiteTunnelPeer(1040)=;SndDSLiteTunnelPeer(1041)=;BeginTime_e(1013)=12012019081051;
     * EndTime_e(1014)=12012019081543;Event(1048)=(1)Normal over;
     * <br/>
     * <189>Dec  4 17:42:33 2019 H3C %%10SHELL/5/SHELL_LOGOUT: admgbzwy@system(@context5) logged out from vty1.
     * <190>Dec  4 17:41:32 2019 H3C %%10SHELL/6/SHELL_CMD: -Line=vty1-IPAddr=**-User=admgbzwy@system(@context5); Command is dis object-policy ip
     * <188>Dec  4 17:41:30 2019 H3C %%10SHELL/4/SHELL_CMD_MATCHFAIL: -User=admgbzwy@system(@context5)-IPAddr=**; Command dis object-policy  in view shell failed to be matched.
     * <189>Dec  4 17:43:06 2019 H3C %%10SHELL/5/SHELL_LOGIN: admgbzwy@system(@context10) logged in from vty1.
     */
    public static Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        String syslog = obj.getStr("syslog");
        // 公共头部处理
        String bo = disPublicLog(syslog, obj);
        // 主体内容处理
        disLog(bo, obj);
        // 必须字段
        obj.put("manufacturers_name", "H3C");
        obj.put("manufacturers_facility", "安全产品");
        obj.put("facility_type", "web");
        return obj;
    }

    /**
     * 主体处理
     */
    private static void disLog(String bo, JSONObject obj) {
        String abs = obj.getStr("abstract");
        if ("SESSION_IPV4_FLOW".equalsIgnoreCase(abs)) {
            HscSafetyProtocol.disLogProtocol(bo, obj);
            obj.put("log_type", "security");
            obj.put("event_type", "session");
        } else if ("IPS_IPV4_INTERZONE".equalsIgnoreCase(abs)) {
            obj.put("log_type", "attack");
            obj.put("event_type", "ips");
            obj.put("event_son_type", "ips");
            HscSafetyProtocol.disLogProtocol(bo, obj);
        } else if (abs.toLowerCase().startsWith("shell")) {
            obj.put("log_type", "security");
            obj.put("event_type", "shell");
            H3cShell.disLogShell(bo, obj);
        } else {
            obj.put("event_type", "other");
            obj.put("message_content", bo);
        }
        obj.put("log_des", "HSC - 安全产品 - " + abs);
    }

    /**
     * 公共部分处理
     */
    private static String disPublicLog(String syslog, JSONObject obj) {
        String[] pubLog = syslog.split(": ");
        String[] head = pubLog[0].split(" %%");
        String[] facilityHostname = head[0].split(" ");
        obj.put("facility_hostname", facilityHostname[facilityHostname.length - 1]);
        String[] he = head[1].split("/");
        String num = he[0].substring(0, 2);
        if (NumberUtil.isNumber(num)) {
            num = he[0].substring(2);
        }
        obj.put("event_type", num);
        obj.put("log_level", he[1]);
        obj.put("abstract", he[2]);
        return pubLog[1];
    }

    /**
     * 是否为 安全产品 日志
     */
    public static boolean isSafety(String syslog) {
        return StringUtil.containsAll(syslog, " %%", ": ") && syslog.split("/").length > 2;
    }
}
