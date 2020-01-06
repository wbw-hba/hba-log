package cn.hba.audit.flume.soc.log.log360;

import cn.hba.audit.flume.soc.SyslogParse;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 360
 *
 * @author wbw
 * @date 2019/9/6 11:16
 */
public class SyslogParse360 implements SyslogParse {

    @Override
    public Object parse(String body) {
        return Bastion360Host.select(body);
    }


    public static void main(String[] args) {
        SyslogParse parse = new SyslogParse360();
        String sys = "20191017 16:00:18 Gateway |5|0x02000465|User|Login|admin|Success|管理员[admin:本地认证]登录系统:IP[2.74.24.21], 接口[GE3], 登录方式[HTTPS],认证服务器为[本地认证], 认证类型[LOCAL].  ";
        JSONObject object = JSONUtil.createObj();
        object.put("syslog", sys);
        Object res = parse.parse(object.toString());
        System.out.println(JSONUtil.parseObj(res).toJSONString(2));
    }
}
