package cn.hba.audit.flume.soc.log.logh3c.safety;

import cn.hba.audit.flume.util.ParseMessageKv;
import cn.hutool.json.JSONObject;

/**
 * session,ips
 *
 * @author wbw
 * @date 2019/12/2 13:32
 */
class HscSafetyProtocol {

    /**
     * 格式：
     * Protocol(1001)=TCP;Application(1002)=general_tcp;SrcIPAddr(1003)=192.168.183.14;SrcPort(1004)=63291;
     * NatSrcIPAddr(1005)=112.35.18.188;NatSrcPort(1006)=56525;DstIPAddr(1007)=117.161.25.21;DstPort(1008)=8200;
     * NatDstIPAddr(1009)=117.161.25.21;NatDstPort(1010)=8200;InitPktCount(1044)=6;InitByteCount(1046)=2234;
     * RplyPktCount(1045)=4;RplyByteCount(1047)=1572;RcvVPNInstance(1042)=;SndVPNInstance(1043)=;
     * RcvDSLiteTunnelPeer(1040)=;SndDSLiteTunnelPeer(1041)=;BeginTime_e(1013)=12012019080919;
     * EndTime_e(1014)=12012019080949;Event(1048)=(1)Normal over;
     * <p>
     * Protocol(1001)=TCP; Application(1002)=ShouJiBaiDu; SrcIPAddr(1003)=192.168.221.213; SrcPort(1004)=43056;
     * DstIPAddr(1007)=192.168.187.11; DstPort(1008)=8020; RcvVPNInstance(1042)=5vuk68gddb8v5bfskaskcaspbu;
     * SrcZoneName(1025)=W7ZIVZIYVZSX5P7VBSEDLK2HZI; DstZoneName(1035)=EXTERNAL; PolicyName(1079)=ips_wznetdttdxod5rofa2i3m6kk7u;
     * AttackName(1088)=INFOMATION_GATHER__Robot_Spider_Crawler(Baidu); AttackID(1089)=23302;
     * Category(1090)=InformationDisclosure; Protection(1091)=WebServer; SubProtection(1092)=Any;
     * Severity(1087)=LOW; Action(1053)=Permit & Logging; CVE(1075)=--; BID(1076)=--; MSB(1077)=--;
     * HitDirection(1115)=original; RealSrcIP(1100)=220.181.108.78; SubCategory(1124)=Spider;
     *
     * @param bo  主体
     * @param obj 结果
     */
    static void disLogProtocol(String bo, JSONObject obj) {
        JSONObject boJson = ParseMessageKv.parseMessage3(bo);
        disBoToJson(boJson, obj);
    }

    /**
     * 统一 公共值处理
     *
     * @param boJson 解析的值
     * @param obj    结果
     */
    private static void disBoToJson(JSONObject boJson, JSONObject obj) {
        if (boJson.containsKey("Protocol(1001)")) {
            obj.put("protocol_type", boJson.getStr("Protocol(1001)"));
        }
        if (boJson.containsKey("Application(1002)")) {
            obj.put("app_protocol", boJson.getStr("Application(1002)"));
        }
        if (boJson.containsKey("SrcIPAddr(1003)")) {
            obj.put("ip", boJson.getStr("SrcIPAddr(1003)"));
        }
        if (boJson.containsKey("SrcPort(1004)")) {
            obj.put("port", boJson.getStr("SrcPort(1004)"));
        }
        if (boJson.containsKey("NatSrcIPAddr(1005)")) {
            obj.put("nat_after_ip", boJson.getStr("NatSrcIPAddr(1005)"));
        }
        if (boJson.containsKey("NatSrcPort(1006)")) {
            obj.put("nat_after_port", boJson.getStr("NatSrcPort(1006)"));
        }
        if (boJson.containsKey("DstIPAddr(1007)")) {
            obj.put("dest_ip", boJson.getStr("DstIPAddr(1007)"));
        }
        if (boJson.containsKey("DstPort(1008)")) {
            obj.put("dest_port", boJson.getStr("DstPort(1008)"));
        }
        if (boJson.containsKey("NatDstIPAddr(1009)")) {
            obj.put("nat_after_dip", boJson.getStr("NatDstIPAddr(1009)"));
        }
        if (boJson.containsKey("NatDstPort(1010)")) {
            obj.put("nat_after_dport", boJson.getStr("NatDstPort(1010)"));
        }
        if (boJson.containsKey("UserName(1113)")) {
            obj.put("user_name", boJson.getStr("UserName(1113)"));
        }
        if (boJson.containsKey("InitPktCount(1044)")) {
            obj.put("init_pkt_count", boJson.getInt("InitPktCount(1044)"));
        }
        if (boJson.containsKey("InitByteCount(1046)")) {
            obj.put("init_byte_count", boJson.getStr("InitByteCount(1046)"));
        }
        if (boJson.containsKey("RplyPktCount(1045)")) {
            obj.put("rply_pkt_count", boJson.getStr("RplyPktCount(1045)"));
        }
        if (boJson.containsKey("RplyByteCount(1047)")) {
            obj.put("rply_byte_count", boJson.getStr("RplyByteCount(1047)"));
        }
        if (boJson.containsKey("RcvVPNInstance(1042)")) {
            obj.put("vpn", boJson.getStr("RcvVPNInstance(1042)"));
        }
        if (boJson.containsKey("SndVPNInstance(1043)")) {
            obj.put("dest_vpn", boJson.getStr("SndVPNInstance(1043)"));
        }
        if (boJson.containsKey("RcvDSLiteTunnelPeer(1040)")) {
            obj.put("ds_lite_tunnel", boJson.getStr("RcvDSLiteTunnelPeer(1040)"));
        }
        if (boJson.containsKey("SndDSLiteTunnelPeer(1041)")) {
            obj.put("dest_ds_lite_tunnel", boJson.getStr("SndDSLiteTunnelPeer(1041)"));
        }
        if (boJson.containsKey("BeginTime_e(1013)")) {
            obj.put("session_begin_time", boJson.getStr("BeginTime_e(1013)"));
        }
        if (boJson.containsKey("EndTime_e(1014)")) {
            obj.put("session_del_time", boJson.getStr("EndTime_e(1014)"));
        }
        if (boJson.containsKey("Event(1048)")) {
            String event = boJson.getStr("Event(1048)");
            if (event.contains("Session created")) {
                obj.put("message_content", "会话创建日志");
            } else if (event.contains("Active flow threshold")) {
                obj.put("message_content", "流量或时间阈值日志");
            } else if (event.contains("Normal over")) {
                obj.put("message_content", "正常流结束，会话删除日志");
            } else if (event.contains("Aged for timeout")) {
                obj.put("message_content", "会话老化删除日志");
            } else if (event.contains("Aged for reset or config-change")) {
                obj.put("message_content", "通过配置删除会话日志");
            } else {
                obj.put("message_content", event);
            }
        }
        if (boJson.containsKey("SrcZoneName(1025)")) {
            obj.put("zone_name", boJson.getStr("SrcZoneName(1025)"));
        }
        if (boJson.containsKey("DstZoneName(1035)")) {
            obj.put("dest_zone_name", boJson.getStr("DstZoneName(1035)"));
        }
        if (boJson.containsKey("PolicyName(1079)")) {
            obj.put("policy_name", boJson.getStr("PolicyName(1079)"));
        }
        if (boJson.containsKey("AttackName(1088)")) {
            obj.put("threat_name", boJson.getStr("AttackName(1088)"));
        }
        if (boJson.containsKey("AttackID(1089)")) {
            obj.put("threat_id", boJson.getStr("AttackID(1089)"));
        }
        if (boJson.containsKey("Category(1090)")) {
            obj.put("attack_type", boJson.getStr("Category(1090)"));
        }
        if (boJson.containsKey("Protection(1091)")) {
            obj.put("protection", boJson.getStr("Protection(1091)"));
        }
        if (boJson.containsKey("SubProtection(1092)")) {
            obj.put("sub_protection", boJson.getStr("SubProtection(1092)"));
        }
        if (boJson.containsKey("Severity(1087)")) {
            String severity = boJson.getStr("Severity(1087)");
            if ("LOW".equalsIgnoreCase(severity)) {
                obj.put("severity_level", ("低"));
            } else if ("MEDIUM".equalsIgnoreCase(severity)) {
                obj.put("severity_level", ("中"));
            } else if ("HIGH".equalsIgnoreCase(severity)) {
                obj.put("severity_level", ("高"));
            } else if ("CRITICAL".equalsIgnoreCase(severity)) {
                obj.put("severity_level", ("严重"));
            } else {
                obj.put("severity_level", ("未指定"));
            }
        }
        if (boJson.containsKey("Action(1053)")) {
            String action = boJson.getStr("Action(1053)");
            action = action.replaceAll("Block-Source", "阻断源")
                    .replaceAll("Drop", "丢包")
                    .replaceAll("Reset", "重置")
                    .replaceAll("Permit", "告警")
                    .replaceAll("Redirect", "重定向")
                    .replaceAll("Capture", "捕获")
                    .replaceAll("Logging", "生成日志");
            obj.put("conduct_operations", action);
        }

        if (boJson.containsKey("CVE(1075)")) {
            obj.put("cve", boJson.getStr("CVE(1075)"));
        }
        if (boJson.containsKey("BID(1076)")) {
            obj.put("bid", boJson.getStr("BID(1076)"));
        }
        if (boJson.containsKey("MSB(1077)")) {
            obj.put("msb", boJson.getStr("MSB(1077)"));
        }
        if (boJson.containsKey("HitDirection(1115)")) {
            obj.put("hit_direction", "original".equalsIgnoreCase(boJson.getStr("HitDirection(1115)").trim())
                    ? "请求方向" : "应答方向");
        }
        if (boJson.containsKey("RealSrcIP(1100)")) {
            obj.put("real_src_ip", boJson.getStr("RealSrcIP(1100)"));
        }
        if (boJson.containsKey("SubCategory(1124)")) {
            obj.put("attack_sub_category", boJson.getStr("SubCategory(1124)"));
        }
        if (boJson.containsKey("Type(1067)")) {
            obj.put("obj_strategy_type", boJson.getStr("Type(1067)"));
        }
        if (boJson.containsKey("SecurityPolicy(1072)")) {
            obj.put("obj_strategy_name", boJson.getStr("SecurityPolicy(1072)"));
        }
        if (boJson.containsKey("RuleID(1078)")) {
            obj.put("obj_strategy_rule_id", boJson.getStr("RuleID(1078)"));
        }
        if (boJson.containsKey("MatchCount(1069)")) {
            obj.put("match_count", boJson.getStr("MatchCount(1069)"));
        }
    }
}
