package cn.hba.audit.flume.soc.log.logsfd;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 思福迪
 *
 * @author wbw
 * @date 2019/9/6 11:17
 */
public class SyslogParseSfd implements SyslogParse {
    @Override
    public Object parse(String body) {
        JSONObject obj = JSONUtil.parseObj(body);
        obj.put("log_des", "思福迪 - 堡垒机 - 系统");
        obj.put("manufacturers_name", "sfd");
        obj.put("event_type", "system");
        obj.put("log_type", "bastion");
        return obj;
    }
}