package cn.hba.audit.flume.soc.log.logsxf;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hutool.core.date.DateUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;


/**
 * @author ztf
 */
public class SyslogParseSxf implements SyslogParse {
    @Override
    public Object parse(String body) {
        JSONObject object = JSONUtil.parseObj(body);
        String syslog = object.getStr("syslog");

        if (SxfFlowLog.isFlowLog(syslog)) {
            //流量日志
            return SxfFlowLog.parse(body);
        } else if (SxfStrategyLog.isStrategyLog(syslog)) {
            //策略日志
            return SxfStrategyLog.parse(body);
        } else if (SxfProcedureLog.isProcedureLog(syslog)){
            // 系统日志
            return SxfProcedureLog.parseProcedureLog(syslog,object);
        }else if (SxfAttackLog.isAttackLog(syslog)) {
            //攻击日志
            return SxfAttackLog.parse(body);
        }
        return null;
    }


    public static void main(String[] args) {
        String log = "<158>Dec  5 03:26:54 b03-security-serverblade 日志类型=未知程序告警;平台ip=192.168.92.42;程序路径=/etc/cron.daily/mlocate;程序大小=208;Hash值=1409384350;风险级别=6;上报日期=1575487561\n";
        //log = "<134>Dec  1 18:37:58 localhost fwlog: 日志类型:流量审计, 应用类型:Other, 用户名/主机:192.168.100.26, 上行流量(KB):14450, 下行流量(KB):38055, 总流量(KB):52505";
        log = "<14>2019-07-03 14:32:34|!secevent|!192.3.222.68|!{\"event_type_sub\": \"E02-2\", \"event_level\": 1, \"event_type\": \"E02\", \"event_time\": \"2019-07-03 09:34:33\", \"extra\": {}, \"event_id\": \"5d1c064fe138230e8677cd6a\", \"ip\": \"3.1.1.1\", \"event_desc\": \"主机对内网发起SSH扫描\", \"device_ip\": \"\", \"behaviour_type\": 4, \"event_name\": \"\", \"mac\": \"\", \"result\": \"主机很可能已被黑客控制，沦为跳板机，企图控制更多的内网其他主机；或为内网用户的恶意行为。如果是被黑客控制，则存在以下风险：\\n1、造成机密信息被窃取，比如机密文件、关键资产的用户名和密码等；\\n2、主机作为“肉鸡”攻击互联网上的其他单位，违反网络安全法，遭致网信办、网安等监管单位的通报处罚。\", \"dest_port\": \"\", \"user_name\": \"\", \"port\": \"\", \"dest_ip\": \"\"}";
        log = "<158>Dec 8 23:00:51 b03-security-serverblade 日志类型=未知程序告警;平台ip=192.168.92.2;程序路径=/usr/local/hb/hbla;程序大小=971088;Hash值=-1582224208;风险级别=6;上报日期=1575817214";

        JSONObject obj = JSONUtil.createObj();
        obj.put("syslog", log);
        SyslogParse parse = new SyslogParseSxf();
        JSONObject object = JSONUtil.parseObj(parse.parse(obj.toString()));
        object.put("teime", DateUtil.date());
        System.out.println(object.toJSONString(2));
    }

}
