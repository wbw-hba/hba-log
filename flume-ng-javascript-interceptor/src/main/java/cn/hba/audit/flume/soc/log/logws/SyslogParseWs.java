package cn.hba.audit.flume.soc.log.logws;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 网神
 *
 * @author wbw
 * @date 2019/11/28 13:23
 */
public class SyslogParseWs implements SyslogParse {


    @Override
    public Object parse(String body) {
        JSONObject object = JSONUtil.parseObj(body);
        String syslog = object.getStr("syslog");

        if (WsAttackLog.isAttackLog(syslog)) {
            // 攻击日志
            return WsAttackLog.parse(body);
        } else if (WsDdosLog.isDdosLog(syslog)) {
            // ddos 日志
            return WsDdosLog.parse(body);
        } else if (WsTamperProofingLog.isTamperProofingLog(syslog)) {
            // 防篡改日志
            return WsTamperProofingLog.parse(body);
        } else if (WsVisitLog.isVisitLog(syslog)) {
            // 访问日志
            return WsVisitLog.parse(body);
        } else if (syslog.contains("-:") && syslog.split("\\|").length > 2) {
            // 此处抛弃审计日志 2010-2-1 11:34:44-:1 audit through 0 from 2.3.4.5 2 2 3 | create [vrrp 0] |
            return null;
        }
        return null;
    }
}
