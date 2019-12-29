package cn.hba.audit.flume.util;

import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * 解析message 返回jsonObject
 *
 * @author wbw
 * @date 2019/9/10 15:48
 */
public class ParseMessageKv {

    /**
     * 解析 以 xxx:
     * 格式： waf: tag:waf_log_login stat_time:2019-07-10 19:46:50 src_ip:2.75.160.102 user:admin
     */
    public static JSONObject parseMessage1(String syslog) {
        return parse1(syslog, " ", ":");
    }

    /**
     * 解析 以 xxx=
     * 格式： waf= tag=waf_log_login stat_time=2019-07-10 19:46:50 src_ip=2.75.160.102 user=admin
     */
    public static JSONObject parseMessage6(String syslog) {
        return parse3(syslog, " ", "=");
    }

    /**
     * 解析 以 xx:xx;
     * 格式： waf:;tag:waf_log_login;stat_time:2019-07-10 19:46:50;src_ip:2.75.160.102;user:admin
     */
    public static JSONObject parseMessage2(String syslog) {
        return parse2(syslog, ";", ":");
    }

    /**
     * 解析 以 xx=;
     * 格式： waf=;tag=waf_log_login;stat_time=2019-07-10 19:46:50;src_ip=2.75.160.102;user=admin
     */
    public static JSONObject parseMessage3(String syslog) {
        return parse2(syslog, ";", "=");
    }

    /**
     * 解析 以 xxx=
     * 格式： waf= tag=waf_log_login stat_time=2019-07-10 19:46:50 src_ip=2.75.160.102 user=admin
     */
    public static JSONObject parseMessage5(String syslog) {
        return parse1(syslog, " ", "=");
    }

    /**
     * 解析以 xx=xx,
     * 格式： waf= ,tag=waf_log_login,stat_time=2019-07-10 19:46:50,src_ip=2.75.160.102,user=admin
     */
    public static JSONObject parseMessage4(String syslog) {
        return parse2(syslog, ",", "=");
    }

    /**
     * 解析以 xx:xx,
     * 格式： 来源:用户(UI), 类型:系统配置, 用户:ns25000{2.74.24.23}, 描述:系统设置:syslog配置 syslog开关 开启服务器IP：2.74.24.21, 端口：514, 编码：UTF-8, 上传日志类型：操作日志, 系统报警日志
     */
    public static JSONObject parseMessage7(String syslog) {
        return parse2(syslog, ", ", ":");
    }

    /**
     * 时间不可以出现在开头或者结尾
     *
     * @param syslog 文本
     * @param shape1 值键区分形式
     * @param shape2 键值区分形式
     * @return JSONObject
     */
    private static JSONObject parse2(String syslog, String shape1, String shape2) {
        JSONObject obj = JSONUtil.createObj();
        syslog = syslog.trim().replaceAll("\n", "").replaceAll("\t", "");
        String[] split = syslog.split(shape1);
        for (String msg : split) {
            if (msg.contains(shape2)) {
                String[] bo = msg.split(shape2);
                obj.put(StrUtil.trim(bo[0]), StrUtil.trim(msg.substring(msg.indexOf(shape2) + 1)));
            }
        }
        return obj;
    }

    /**
     * 时间不可以出现在开头或者结尾
     * waf
     * tag
     * waf_log_login stat_time
     * 2019-07-10 19
     * 46
     * 50 src_ip
     * 2.75.160.102 user
     * admin
     */
    private static JSONObject parse1(String syslog, String shape1, String shape2) {
        JSONObject obj = JSONUtil.createObj();
        syslog = syslog.trim().replaceAll("\n", "").replaceAll("\t", "");
        String[] split = syslog.split(shape2);
        for (int i = 0; i < split.length; i++) {
            if (i == 0) {
            } else if (i == split.length - 1) {
                String[] last = split[i - 1].split(shape1);
                obj.put(last[last.length - 1].trim(), split[i].replaceAll("\"", ""));
            } else {
                // 此处包含时间特殊处理
                if (NumberUtil.isNumber(split[i]) && StringUtil.containsAll(split[i - 1], "-", " ")) {
                    String val = split[i - 1] + ":" + split[i] + ":" + split[++i].split(shape1)[0];
                    obj.put(StrUtil.toUnderlineCase(split[i - 3].split(shape1)[1].trim()), val.replaceAll("\"", ""));
                    obj.put(StrUtil.toUnderlineCase(split[i].split(shape1)[1].trim()), split[i + 1].split(shape1)[0].replaceAll("\"", ""));
                } else {
                    Map<String, Object> map = disPubBo(split, shape1, i);
                    obj.put(map.get("key").toString(), map.get("val").toString().replaceAll("\"", ""));
                    i = NumberUtil.parseInt(map.get("i").toString());
                }
            }
        }
        return obj;
    }

    private static JSONObject parse3(String syslog, String shape1, String shape2) {
        JSONObject obj = JSONUtil.createObj();
        syslog = syslog.trim().replaceAll("\n", "")
                .replaceAll("\t", "").replaceAll("\"", "");
        String[] split = syslog.split(shape2);
        for (int i = 0; i < split.length; i++) {
            if (i == 0) {
            } else if (i == split.length - 1) {
                String[] last = split[i - 1].split(shape1);
                obj.put(last[last.length - 1].trim(), split[i]);
            } else {
                // 此处包含时间特殊处理
                if (NumberUtil.isNumber(split[i]) && StringUtil.containsAll(split[i - 1], "-", " ")) {
                    String val = split[i - 1] + ":" + split[i] + ":" + split[++i].split(shape1)[0];
                    obj.put(StrUtil.toUnderlineCase(split[i - 3].split(shape1)[1].trim()), val);
                    obj.put(StrUtil.toUnderlineCase(split[i].split(shape1)[1].trim()), split[i + 1].split(shape1)[0]);
                } else {
                    Map<String, Object> map = disPubBo(split, shape1, i);
                    obj.put(map.get("key").toString(), map.get("val"));
                    i = NumberUtil.parseInt(map.get("i").toString());
                }
            }
        }
        return obj;
    }

    /**
     * 公共部分提取
     */
    private static Map<String, Object> disPubBo(String[] split, String shape1, int i) {
        Map<String, Object> map = new HashMap<>(3);
        String[] keys = split[i - 1].split(shape1);
        String[] vals = split[i].split(shape1);
        // 此处防止 args=username=vardenaf&content=%3 这种
        if (vals.length == 1) {
            StringBuilder va = new StringBuilder();
            va.append(vals[0]);
            va.append("=");
            do {
                va.append(split[++i]);
                vals = (va.toString()).split(shape1);
            } while (vals.length == 1);
            split[i] = va.toString();
        }
        String key = StrUtil.toUnderlineCase(keys[keys.length - 1].trim());
        String val = split[i].replace((shape1 + vals[vals.length - 1]), "");
        if (("https".equalsIgnoreCase(val) || "http".equalsIgnoreCase(val))
                && i + 1 < split.length - 1 && StringUtil.containsAll(split[i + 1], "//", ".")) {
            val += ":" + split[++i].split(shape1)[0];
        }
        map.put("key", key);
        map.put("val", val);
        map.put("i", i);
        return map;
    }

    public static void main(String[] args) {
        String a = "devicename=RayOS url=/NewsPL_save.asp method=POST args=username=vardenaf&content=%3 flag_field=48 block_time=0 http_type=HTTP attack_field=32 profile_id=1 rule_id=3004 type=8 severity=2 action=ERROR_CODE 404 referer=http://www.abc.com useragent=Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36 post=userid=%27+or+%27%27%3D%27&pwd=%27+or+%27%27%3D%27&B1=Submit%3D%27&B1=Submit";
        System.out.println(parseMessage5(a).toJSONString(2));
    }


}
