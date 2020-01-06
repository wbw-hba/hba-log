package cn.hba.audit.flume.soc.log.logwk;

import cn.hba.audit.flume.soc.SyslogParse;

/**
 * 网康
 *
 * @author wbw
 * @date 2019/10/21 10:40
 */
public class SyslogParseWk implements SyslogParse {
    @Override
    public Object parse(String body) {
        return WkParse.parse(body);
    }
}
