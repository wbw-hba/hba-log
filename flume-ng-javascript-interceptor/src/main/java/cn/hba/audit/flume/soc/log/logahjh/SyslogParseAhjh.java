package cn.hba.audit.flume.soc.log.logahjh;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 安和金华
 *
 * @author wbw
 * @date 2020/1/7 16:23
 */
public class SyslogParseAhjh implements SyslogParse {

    @Override
    public Object parse(String body) {
        JSONObject object = JSONUtil.parseObj(body);
        String syslog = object.getStr("syslog");
        if (DbFwLog.isDbFwLog(syslog)) {
            // 数据库防火墙日志
            return DbFwLog.parse(body);
        }
        return null;
    }

    public static void main(String[] args) {
        JSONObject obj = JSONUtil.createObj();
        String log = "<8>Dec 22 01:30:25 DBF35M DBFW: CEF:192.168.81.209:514|发生时间:2019-12-22 01:30:15|服务器IP:192.168.101.13|服务器端口:3306|数据库实例名:mysql|数据库版本:MySQL 5.700|客户端IP:192.168.101.1|客户端端口:35640|客户端MAC:000000000000|数据库用户:ELSSP|操作系统用户:无信息|风险类型[风险级别]:操作违规[高] |引擎动作:放行|规则名称:高危操作_yw|SQL报文:DROP TABLE ELSSP.CATALOG_TO_DEL";
        obj.put("syslog", log);

        SyslogParse parse = new SyslogParseAhjh();
        System.out.println(JSONUtil.parse(parse.parse(obj.toString())).toJSONString(2));
        ;
    }
}
