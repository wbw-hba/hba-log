package cn.hba.audit.flume.soc.log.loghw;

import cn.hba.audit.flume.soc.SyslogParse;

/**
 * 华为
 *
 * @author wbw
 * @date 2019/9/6 11:16
 */
public class SyslogParseHw implements SyslogParse {

    @Override
    public Object parse(String body) {
        return InterchangerParse.parse(body);
    }
}
