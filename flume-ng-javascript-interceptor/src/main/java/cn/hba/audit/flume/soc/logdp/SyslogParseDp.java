package cn.hba.audit.flume.soc.logdp;

import cn.hba.audit.flume.soc.SyslogParse;

/**
 * 迪普
 *
 * @author wbw
 * @date 2019/9/6 11:16
 */
public class SyslogParseDp implements SyslogParse {

    @Override
    public Object parse(String body) {
        return BastionHost.parse( body);
    }
}
