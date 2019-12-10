package cn.hba.audit.flume.soc.logtrx;

import cn.hba.audit.flume.soc.SyslogParse;

/**
 * 天融信
 *
 * @author wbw
 * @date 2019/9/6 11:18
 */
public class SyslogParseTrx implements SyslogParse {

    @Override
    public Object parse(String body) {
        return BastionTrxHost.parse(body);
    }
}
