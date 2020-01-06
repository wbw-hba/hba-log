package cn.hba.audit.flume.soc.log.logh3c;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hba.audit.flume.soc.log.logh3c.audit.H3cAuthentication;
import cn.hba.audit.flume.soc.log.logh3c.safety.HscSafety;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * H3C
 *
 * @author wbw
 * @date 2019/11/18 13:31
 */
public class SyslogParseH3c implements SyslogParse {
    @Override
    public Object parse(String body) {
        JSONObject object = JSONUtil.parseObj(body);
        String syslog = object.getStr("syslog");

        if (HscSafety.isSafety(syslog)) {
            // 安全产品
            return HscSafety.parse(body);
        } else if (H3cAuthentication.isAuthentication(syslog)) {
            // 运维审计  身份验证
            JSONObject obj = JSONUtil.parseObj(H3cAuthentication.authParse(body));
            obj.put("module_type", "yunwei");
            obj.put("system_type", "audit");
            return obj;
        }else if(H3cAuthentication.isProperty(syslog)){
            JSONObject obj = JSONUtil.parseObj(H3cAuthentication.propertyParse(body));
            obj.put("module_type", "yunwei");
            obj.put("system_type", "audit");
            //运维审计  资产验证
            return obj;
        }

        return H3cParse.parseSyslog(body);
    }


    public static void main(String[] args) {
        String log = "<6> Dec 01 16:15:43 2019 GB-ZWY-HLWQ-J1J2-S-FW-F1050-1&2 %%10session/6/SESSION_IPV4_FLOW: Protocol(1001)=TCP;Application(1002)=http;SrcIPAddr(1003)=192.168.187.12;SrcPort(1004)=40912;NatSrcIPAddr(1005)=112.35.18.188;NatSrcPort(1006)=9460;DstIPAddr(1007)=47.95.12.238;DstPort(1008)=80;NatDstIPAddr(1009)=47.95.12.238;NatDstPort(1010)=80;InitPktCount(1044)=1;InitByteCount(1046)=60;RplyPktCount(1045)=0;RplyByteCount(1047)=0;RcvVPNInstance(1042)=;SndVPNInstance(1043)=;RcvDSLiteTunnelPeer(1040)=;SndDSLiteTunnelPeer(1041)=;BeginTime_e(1013)=12012019081543;EndTime_e(1014)=;Event(1048)=(8)Session created;\n";
//        log = "<188>Dec  1 19:35:56 2019 H3C %%10IPS/4/IPS_IPV4_INTERZONE: Protocol(1001)=TCP; Application(1002)=ShouJiBaiDu; SrcIPAddr(1003)=192.168.221.39; SrcPort(1004)=33580; DstIPAddr(1007)=192.168.187.12; DstPort(1008)=8020; RcvVPNInstance(1042)=5vuk68gddb8v5bfskaskcaspbu; SrcZoneName(1025)=W7ZIVZIYVZSX5P7VBSEDLK2HZI; DstZoneName(1035)=EXTERNAL; PolicyName(1079)=ips_wznetdttdxod5rofa2i3m6kk7u; AttackName(1088)=INFOMATION_GATHER__Robot_Spider_Crawler(Baidu); AttackID(1089)=23302; Category(1090)=InformationDisclosure; Protection(1091)=WebServer; SubProtection(1092)=Any; Severity(1087)=LOW; Action(1053)=Permit & Logging; CVE(1075)=--; BID(1076)=--; MSB(1077)=--; HitDirection(1115)=original; RealSrcIP(1100)=220.181.108.78; SubCategory(1124)=Spider; \n";
//        log="<134>Dec 04 15:12:35 node1 H3C-A2020-G: Login(web)(service=native server=None(None) account=None identity=h3cadmin from=172.31.255.2 login authorize success)";
//        log="<134>Dec 04 15:41:19 node1 H3C-A2020-G: bljuser10 from interface(service=gui login server=group10-3(192.168.109.71) account=any identity=bljuser10 from=192.168.6.154 )";
//       log = "<190> Dec 24 02:55:12 2019 GB-ZWY-HLWQ-J1J2-S-FW-F1050-1&2 %%10FILTER/6/FILTER_ZONE_IPV4_EXECUTION: SrcZoneName(1025)=Untrust;DstZoneName(1035)=Trust;Type(1067)=ACL;SecurityPolicy(1072)=hanbang_514;RuleID(1078)=174;Protocol(1001)=TCP;Application(1002)=general_tcp;SrcIPAddr(1003)=183.131.177.241;SrcPort(1004)=4220;DstIPAddr(1007)=192.168.202.205;DstPort(1008)=50006;MatchCount(1069)=1;Event(1048)=Permit;\",\"abstract\": \"FILTER_ZONE_IPV4_EXECUTION";
        log = "<190> Dec 28 13:12:54 2019 GB-ZWY-HLWQ-J1J2-S-FW-F1050-1&2 %%10FILTER/6/FILTER_ZONE_IPV4_EXECUTION: SrcZoneName(1025)=Untrust;DstZoneName(1035)=Trust;Type(1067)=ACL;SecurityPolicy(1072)=server_work_newn;RuleID(1078)=101;Protocol(1001)=TCP;Application(1002)=general_tcp;SrcIPAddr(1003)=47.96.234.43;SrcPort(1004)=63117;DstIPAddr(1007)=192.168.221.133;DstPort(1008)=80;MatchCount(1069)=1;Event(1048)=Permit;\",\"abstract\": \"FILTER_ZONE_IPV4_EXECUTION";
        JSONObject obj = JSONUtil.createObj();
        obj.put("syslog", log);
        SyslogParse parse = new SyslogParseH3c();
        System.out.println(JSONUtil.parseObj(parse.parse(obj.toString())).toJSONString(2));
    }
}
