package cn.hba.audit.flume.soc.log.logwyxy;

import cn.hba.audit.flume.soc.SyslogParse;

/**
 * 网御星云
 *
 * @author wbw
 * @date 2019/9/6 11:19
 */
public class SyslogParseWyxy implements SyslogParse {

    @Override
    public Object parse(String body) {
        return WyxyParse.parse(body);
    }
}
