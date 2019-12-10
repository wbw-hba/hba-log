package cn.hba.audit.flume.soc.logsxf;

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
        }
        return null;
    }


    public static void main(String[] args) {
        String log = "<158>Dec  5 03:26:54 b03-security-serverblade 日志类型=未知程序告警;平台ip=192.168.92.42;程序路径=/etc/cron.daily/mlocate;程序大小=208;Hash值=1409384350;风险级别=6;上报日期=1575487561\n";
        //log = "<134>Dec  1 18:37:58 localhost fwlog: 日志类型:流量审计, 应用类型:Other, 用户名/主机:192.168.100.26, 上行流量(KB):14450, 下行流量(KB):38055, 总流量(KB):52505";
        JSONObject obj = JSONUtil.createObj();
        obj.put("syslog", log);
        SyslogParse parse = new SyslogParseSxf();
        JSONObject object = JSONUtil.parseObj(parse.parse(obj.toString()));
        object.put("teime", DateUtil.date());
        System.out.println(object.toJSONString(2));
    }

}
