package cn.hba.audit.flume.soc.log.loglm;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hba.audit.flume.soc.log.loglm.ads.AdsDdosParse;
import cn.hba.audit.flume.soc.log.loglm.sas.SasParse;
import cn.hba.audit.flume.soc.log.loglm.waf.WafParse;
import cn.hba.audit.flume.util.StringUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 绿盟
 *
 * @author wbw
 * @date 2019/9/6 11:17
 */
public class SyslogParseLm implements SyslogParse {

    @Override
    public Object parse( String body) {
        String syslog = JSONUtil.parseObj(body).getStr("syslog");
        // waf
        if (StringUtil.containsAll(syslog," waf: ","waf_log_")) {
            return WafParse.parse( body);
        } else if (AdsDdosParse.isAds(syslog)) {
            // ads ddos
            return AdsDdosParse.parse(body);
        } else if (SasParse.isSas(syslog)){
            return SasParse.parse(body);
        }

        return null;
    }

    public static void main(String[] args) {
        String log = "<255>user:weboper;loginip:2.74.24.29;time:2019-09-25 15:42:55;type:1;\n" +
                "登录成功";

        JSONObject object = JSONUtil.createObj();
        object.put("syslog", log);
        SyslogParse syslogParse = new SyslogParseLm();
        System.out.println(JSONUtil.parseObj(syslogParse.parse(object.toString())).toJSONString(2));
    }
}
